'use strict';
const $=id=>document.getElementById(id);let token='';
const mailLabels={off:'выключены',waiting:'ожидает отправки',sending:'отправляется / результат ещё неизвестен',accepted:'письмо принято почтовым сервисом',failed:'не удалось отправить',not_configured:'отправка писем не настроена',retry_expired:'повторная отправка уже недоступна'};
async function api(path,body){
  const response=await fetch(path,{method:body?'POST':'GET',headers:{'Content-Type':'application/json',...(token?{Authorization:'Bearer '+token}:{})},...(body?{body:JSON.stringify(body)}:{})});
  let result;try{result=await response.json();}catch{throw Error('Сервер недоступен. Попробуй ещё раз.');}
  if(!response.ok){if(response.status===403&&token){token='';$('panel').hidden=true;$('login').hidden=false;}throw Error(result.error||'Запрос не выполнен');}return result;
}
async function action(button,fn){button.disabled=true;try{await fn();}catch(e){$('status').textContent=e.message;}finally{button.disabled=false;}}
function showMode(){$('free-products').hidden=$('mode').value!=='automatic';}
$('mode').addEventListener('change',showMode);
async function load(initial=false){
  const result=await api('/api/moderation');
  if(initial){$('mode').value=result.settings.mode;$('products').value=result.settings.products.join(', ');$('notify').checked=result.settings.notify;$('recipient').value=result.settings.recipient;showMode();}
  $('mail-state').textContent=result.mailConfigured?'Отправка писем подключена. Статус доставки смотри у своего почтового провайдера.':'Отправка писем пока не подключена. Заявки всё равно будут видны ниже.';
  $('requests').replaceChildren();
  if(!result.requests.length){const empty=document.createElement('p');empty.textContent='Новых заявок пока нет.';$('requests').append(empty);}
  for(const r of result.requests){
    const card=document.createElement('article');card.className='request';
    const title=document.createElement('h3');title.textContent=r.player+' · '+r.product;card.append(title);
    for(const [label,value] of [['Сертификат',r.certificate],['Телефон',r.phone],['Email',r.email||'не указан'],['Комментарий',r.note||'нет'],['Создана',new Date(r.created*1000).toLocaleString()],['Письмо',mailLabels[r.mail_status]||r.mail_status]]){
      const line=document.createElement('p');line.textContent=label+': '+value;card.append(line);
    }
    const row=document.createElement('div');row.className='row';
    for(const [kind,label] of [['approve','Одобрить'],['reject','Отклонить'],...(['failed','not_configured'].includes(r.mail_status)?[['retry-mail','Повторить письмо']]:[])]){
      const button=document.createElement('button');button.textContent=label;button.className=kind==='approve'?'':'secondary';
      button.addEventListener('click',()=>action(button,async()=>{
        const result=await api('/api/moderation/'+r.id+'/'+kind,{});
        $('status').textContent=kind==='retry-mail'?'Письмо: '+(mailLabels[result.mailStatus]||result.mailStatus):kind==='approve'?'Игрок одобрен. Теперь он может начать вход из игры.':'Заявка отклонена.';
        await load();
      }));row.append(button);
    }card.append(row);$('requests').append(card);
  }
}
$('login').addEventListener('submit',event=>{event.preventDefault();action(event.submitter,async()=>{
  const result=await api('/api/moderation/login',{phone:$('phone').value.trim(),password:$('password').value});token=result.token;$('password').value='';
  await load(true);$('login').hidden=true;$('panel').hidden=false;$('status').textContent='Вход выполнен. Настройки действуют после сохранения.';
});});
$('settings').addEventListener('submit',event=>{event.preventDefault();action(event.submitter,async()=>{
  await api('/api/moderation/settings',{mode:$('mode').value,products:$('products').value.split(',').map(v=>v.trim()).filter(Boolean),notify:$('notify').checked,recipient:$('recipient').value.trim()});
  $('status').textContent='Настройки регистрации сохранены.';await load();
});});
$('reload').addEventListener('click',()=>action($('reload'),()=>load()));
$('logout').addEventListener('click',()=>action($('logout'),async()=>{await api('/api/moderation/logout',{});token='';$('panel').hidden=true;$('login').hidden=false;$('requests').replaceChildren();$('status').textContent='Вы вышли.';}));
