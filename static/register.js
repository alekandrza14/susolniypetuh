'use strict';
const $=id=>document.getElementById(id);
let certificate=null,request=null;
const fields=['schema','licenseStatus','grantType','signature','issuedAt','expiresAt','playerId','productId','certificateId','payment'];
function selectCertificate(value){
  if(!value||value.schema!=='myengine-license/v1'||!value.playerId||!value.productId||!value.certificateId)throw Error('Нужен JSON-сертификат MyEngine.');
  certificate=Object.fromEntries(fields.filter(k=>Object.hasOwn(value,k)).map(k=>[k,value[k]]));
  $('certificate-info').textContent=`Игрок: ${certificate.playerId} · Товар: ${certificate.productId}`;
}
try{
  const hash=location.hash;history.replaceState(null,'',location.pathname);
  if(hash.startsWith('#certificate=')&&hash.length<=12000)selectCertificate(JSON.parse(decodeURIComponent(hash.slice(13))));
}catch(e){$('status').textContent='Не удалось прочитать сертификат из игры. Выбери файл вручную.';}
async function api(path,body,token){
  const response=await fetch(path,{method:body?'POST':'GET',headers:{'Content-Type':'application/json',...(token?{Authorization:'Bearer '+token}:{})},...(body?{body:JSON.stringify({...body,device:window.MyEngineDevice.read()})}:{})});
  let result;try{result=await response.json();}catch{throw Error('Сервер недоступен. Попробуй ещё раз.');}
  if(!response.ok)throw Error(result.error||'Запрос не выполнен');return result;
}
async function action(button,fn){button.disabled=true;try{await fn();}catch(e){$('status').textContent=e.message;}finally{button.disabled=false;}}
$('certificate').addEventListener('change',async()=>{
  certificate=null;const file=$('certificate').files[0];if(!file)return;
  try{if(file.size>65536)throw Error('Сертификат слишком большой.');selectCertificate(JSON.parse((await file.text()).replace(/^\uFEFF/,'')));$('status').textContent='';}
  catch(e){$('certificate-info').textContent='Файл не принят';$('status').textContent=e.message;}
});
$('registration-form').addEventListener('submit',event=>{
  event.preventDefault();action($('submit'),async()=>{
    if(!certificate)throw Error('Выбери сертификат из игры.');
    request=await api('/api/registrations',{certificate,phone:$('phone').value.trim(),email:$('email').value.trim(),note:$('note').value,paymentAvailability:$('payment-availability').value});
    $('registration-form').hidden=true;
    if(request.status==='code_required'){$('code-form').hidden=false;$('code').focus();$('status').textContent='Отправлен запрос на SMS. Введи код, который придёт на твой номер.';}
    else{
      const draft=request.emailDraft;
      if(!draft||typeof draft.href!=='string'||!draft.href.startsWith('mailto:'))throw Error('Заявка сохранена, но письмо не подготовлено. Обратись к автору.');
      $('mail-to').value=draft.to;$('mail-subject').value=draft.subject;$('mail-body').value=draft.body;
      $('write-email').href=draft.href;$('email-draft').hidden=false;$('refresh').hidden=false;
      $('status').textContent='Заявка сохранена. Теперь отправь письмо #verify автору. Письмо ещё не отправлено, доступ ожидает одобрения.';
    }
  });
});
$('code-form').addEventListener('submit',event=>{
  event.preventDefault();action(event.submitter,async()=>{
    await api('/api/registrations/'+request.id+'/code',{code:$('code').value.trim()},request.token);
    $('code-form').hidden=true;$('status').textContent='Регистрация завершена! Вернись в игру и выбери этот же сертификат для входа.';
  });
});
$('refresh').addEventListener('click',()=>action($('refresh'),async()=>{
  const result=await api('/api/registrations/'+request.id,null,request.token);
  const labels={pending:'Автор ещё не рассмотрел заявку.',approved:'Автор одобрил регистрацию! Вернись в игру и выбери тот же сертификат.',rejected:'Автор отклонил заявку. Свяжись с автором игры.',expired:'Срок заявки истёк. Обнови страницу и отправь новую заявку.'};
  $('status').textContent=labels[result.status]||'Заявка обрабатывается.';
  if(['approved','rejected','expired'].includes(result.status))$('refresh').hidden=true;
}));
$('copy-email').addEventListener('click',()=>action($('copy-email'),async()=>{
  try{await navigator.clipboard.writeText($('mail-body').value);$('status').textContent='Текст скопирован. Вставь его в письмо с темой #verify и отправь автору.';}
  catch{$('mail-body').focus();$('mail-body').select();$('status').textContent='Текст выделен. Нажми Ctrl+C или выбери «Копировать».';}
}));
api('/api/registration/config').then(config=>{
  if(config.mode==='closed'){$('mode').textContent='Автор пока не открыл регистрацию. Если у тебя уже есть доступ, начни вход из игры.';return;}
  $('registration-form').hidden=false;$('payment-question').hidden=config.mode!=='approval';
  $('mode').textContent=config.mode==='approval'?'Подготовь письмо с темой #verify и отправь его автору из своей почты. Автор рассмотрит заявку. Телефон будет проверен по SMS при входе.':'Подтверди телефон по SMS, чтобы получить свободный доступ. Доступные товары: '+config.products.join(', ')+'.';
  $('submit').textContent=config.mode==='approval'?'Подготовить письмо #verify':'Получить SMS-код';
}).catch(e=>{$('mode').textContent='Не удалось загрузить настройки регистрации.';$('status').textContent=e.message;});
