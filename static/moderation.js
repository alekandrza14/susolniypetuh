'use strict';
const $=id=>document.getElementById(id);let token='';
async function api(path,body){
  const response=await fetch(path,{method:body?'POST':'GET',headers:{'Content-Type':'application/json',...(token?{Authorization:'Bearer '+token}:{})},...(body?{body:JSON.stringify({...body,device:window.MyEngineDevice.read()})}:{})});
  let result;try{result=await response.json();}catch{throw Error('Сервер недоступен. Попробуй ещё раз.');}
  if(!response.ok){if(response.status===403&&token&&result.code==='owner_session_required'){token='';$('panel').hidden=true;$('login').hidden=false;}throw Error(result.error||'Запрос не выполнен');}return result;
}
async function action(button,fn){button.disabled=true;try{await fn();}catch(e){$('status').textContent=e.message;}finally{button.disabled=false;}}
function showMode(){$('free-products').hidden=$('mode').value!=='automatic';}
$('mode').addEventListener('change',showMode);
async function load(initial=false){
  const result=await api('/api/moderation');
  if(initial){$('mode').value=result.settings.mode;$('products').value=result.settings.products.join(', ');$('recipient').value=result.settings.recipient;showMode();}
  $('requests').replaceChildren();
  if(!result.requests.length){const empty=document.createElement('p');empty.textContent='Новых заявок пока нет.';$('requests').append(empty);}
  for(const r of result.requests){
    const card=document.createElement('article');card.className='request';
    const title=document.createElement('h3');title.textContent=r.player+' · '+r.product;card.append(title);
    for(const [label,value] of [['ID заявки',r.id],['Сертификат',r.certificate],['Телефон',r.phone],['Email',r.email||'не указан'],['Комментарий',r.note||'нет'],['Создана',new Date(r.created*1000).toLocaleString()]]){
      const line=document.createElement('p');line.textContent=label+': '+value;card.append(line);
    }
    const claims=r.claims||{};
    const summary=document.createElement('p');summary.textContent='Права: обычный игрок. Тип в файле: '+(claims.grant_type||'неизвестен')+'. Оплата сервером не подтверждена.';card.append(summary);
    if(claims.payment_availability==='unavailable'){const warning=document.createElement('p');warning.className='warning';warning.textContent='Игрок сообщил: способ оплаты недоступен. Требуется обсуждение оплаты, это не доказательство подделки.';card.append(warning);}
    const reason=document.createElement('select');reason.setAttribute('aria-label','Основание доступа');
    for(const [value,label] of [['manual_access','Разрешаю доступ; оплата не проверена'],['free_grant','Выдаю бесплатный доступ'],['purchase_reviewed','Лично проверил покупку']]){const option=document.createElement('option');option.value=value;option.textContent=label;reason.append(option);}card.append(reason);
    const reference=document.createElement('input');reference.placeholder='Номер лично проверенной операции';reference.maxLength=120;reference.hidden=true;reference.setAttribute('aria-label','Номер проверенной операции');reason.addEventListener('change',()=>{reference.hidden=reason.value!=='purchase_reviewed';});card.append(reference);
    const row=document.createElement('div');row.className='row';
    for(const [kind,label] of [['approve','Одобрить'],['reject','Отклонить']]){
      const button=document.createElement('button');button.textContent=label;button.className=kind==='approve'?'':'secondary';
      button.addEventListener('click',()=>action(button,async()=>{
        const result=await api('/api/moderation/'+r.id+'/'+kind,{accessReason:reason.value,paymentReference:reference.value});
        $('status').textContent=kind==='approve'?'Игрок одобрен. Теперь он может начать вход из игры.':'Заявка отклонена.';
        await load();
      }));row.append(button);
    }card.append(row);$('requests').append(card);
  }
}
$('login').addEventListener('submit',event=>{event.preventDefault();action(event.submitter,async()=>{
  const result=await api('/api/moderation/login',{phone:$('phone').value.trim(),password:$('password').value});token=result.token;$('password').value='';
  await load(true);await loadSecurity();$('login').hidden=true;$('panel').hidden=false;$('status').textContent='Вход выполнен. Настройки действуют после сохранения.';
});});
$('settings').addEventListener('submit',event=>{event.preventDefault();action(event.submitter,async()=>{
  await api('/api/moderation/settings',{mode:$('mode').value,products:$('products').value.split(',').map(v=>v.trim()).filter(Boolean),recipient:$('recipient').value.trim()});
  $('status').textContent='Настройки регистрации сохранены.';await load();
});});
$('reload').addEventListener('click',()=>action($('reload'),()=>load()));
$('logout').addEventListener('click',()=>action($('logout'),async()=>{await api('/api/moderation/logout',{});token='';$('panel').hidden=true;$('login').hidden=false;$('requests').replaceChildren();$('security-events').replaceChildren();$('owner-password').value='';$('status').textContent='Вы вышли.';}));
let securityNext=null,developerBinding=null,ownerCertificates=[];
const flagNames={different_ip:'Другой IP относительно прошлого входа',different_device:'Другой идентификатор браузера',different_browser:'Изменился браузер / версия',first_observed_login:'Первый наблюдаемый вход',ip_unverified:'IP из заголовка прокси — не подтверждён',developer_claim:'Файл заявляет права разработчика',developer_claim_blocked:'Заявка с типом «разработчик» отклонена',developer_mismatch:'ID не совпадает с закреплённым сертификатом',certificate_denied:'Сертификат не допущен сервером',payment_not_verified:'Оплата не подтверждена сервером',payment_unavailable_reported:'Игрок сообщил о недоступности оплаты',login_failed:'Вход не подтверждён'};
const actionNames={moderator_login:'Вход в кабинет модератора',player_login:'Подтверждение входа в игру',session_request:'Запрос входа из игры',registration_request:'Заявка на регистрацию',developer_binding:'Изменение сертификата владельца',revoke_other_sessions:'Завершение остальных сеансов кабинета',registration_approve:'Одобрение заявки',registration_reject:'Отклонение заявки'};
function appendLegalReference(card,event){
  // Explain selected server refusals, never infer guilt from device or payment metadata.
  if(event.result!=='denied')return;
  const flags=new Set(event.flags||[]);let reason='';
  if(event.action==='session_request'&&flags.has('developer_mismatch')){
    reason='Сертификат в запросе не совпал с закреплённым сертификатом владельца.';
  }else if((event.action==='session_request'&&flags.has('developer_claim')&&flags.has('certificate_denied'))||
           (event.action==='registration_request'&&flags.has('developer_claim_blocked'))){
    reason='Отклонён запрос с заявленным типом сертификата «разработчик».';
  }
  if(!reason)return;
  const details=document.createElement('details');details.className='legal-reference';
  const summary=document.createElement('summary');summary.textContent='Правовая справка: ст. 272 и 159.6 УК РФ';details.append(summary);
  const context=document.createElement('p');context.textContent=reason+' Проверь происхождение файла и настройки: возможны старый сертификат или ошибка. Подделка, личность отправителя и нарушение закона этим событием не установлены.';details.append(context);
  const references=[
    ['Ст. 272 УК РФ — неправомерный доступ к компьютерной информации',
     'Для применения статьи нужны признаки неправомерного доступа к охраняемой законом компьютерной информации и вызванного им уничтожения, блокирования, изменения либо копирования информации. Отклонённый запрос сам по себе этого не доказывает.',
     'https://www.consultant.ru/document/cons_doc_LAW_10699/5c337673c261a026c476d578035ce68a0ae86da0/'],
    ['Ст. 159.6 УК РФ — мошенничество в сфере компьютерной информации',
     'Для применения статьи нужны признаки хищения чужого имущества или приобретения права на чужое имущество посредством вмешательства в компьютерную информацию. Отсутствие подтверждения оплаты или недоступность способа оплаты сами по себе этого не доказывают.',
     'https://www.consultant.ru/document/cons_doc_LAW_10699/51c53d82b60ac8c009745bdea3838d507064c6d3/']
  ];
  for(const [title,text,url] of references){
    const p=document.createElement('p'),link=document.createElement('a');link.textContent=title;link.href=url;link.target='_blank';link.rel='noopener noreferrer';p.append(link);details.append(p);
    const explanation=document.createElement('p');explanation.textContent=text;details.append(explanation);
  }
  const note=document.createElement('p');note.className='hint';note.textContent='Общая справочная информация, не юридическое заключение. Применимость статей оценивается по обстоятельствам дела; для конкретного случая обратись к юристу. Справка не меняет доступ и не присваивает игроку нарушение.';details.append(note);
  card.append(details);
}
async function loadSecurity(more=false){
  const result=await api('/api/moderation/security',more?{before:securityNext}:null);
  if(!more)$('security-events').replaceChildren();
  $('audit-warning').hidden=result.auditHealthy!==false;
  for(const event of result.events){
    const meta=event.metadata||{};const card=document.createElement('article');card.className='event'+(event.flags.some(f=>!['ip_unverified','first_observed_login'].includes(f))?' flagged':'');
    const title=document.createElement('strong');title.textContent=(actionNames[event.action]||event.action)+' · '+({verified:'успешно',accepted:'запрос принят',denied:'отклонён'}[event.result]||event.result);card.append(title);
    const lines=[new Date(event.created*1000).toLocaleString()+' · Игрок / аккаунт: '+(event.actor||'не определён'),
      'Права подтверждены: '+({owner:'владелец',player:'игрок',unverified:'нет'}[event.role]||event.role),
      'IP: '+(meta.ip||'неизвестен')+(meta.ipSource==='proxy_header_unverified'?' (заголовок прокси)':''),
      'Браузер: '+meta.browser+' · Система: '+meta.os,
      'Название устройства: '+(meta.deviceName||'не указано')+' (со слов пользователя)'];
    if(meta.peer&&meta.peer!==meta.ip)lines.push('Адрес соединения с сервером: '+meta.peer);
    if(meta.subjectPlayer)lines.push('Заявитель: '+meta.subjectPlayer);
    if(meta.accessReason)lines.push('Основание: '+({manual_access:'Разрешение автора без проверки оплаты',free_grant:'Бесплатный доступ',purchase_reviewed:'Автор проверил покупку лично'}[meta.accessReason]||meta.accessReason));
    if(meta.paymentReference)lines.push('Указанный автором номер операции: '+meta.paymentReference);
    if(event.certificate)lines.push('Сертификат: '+event.certificate+' · Товар: '+event.product);
    for(const text of lines){const p=document.createElement('p');p.textContent=text;card.append(p);}
    if(event.flags.length){const p=document.createElement('p');p.className='warning';p.textContent=event.flags.map(f=>flagNames[f]||f).join('; ');card.append(p);}
    appendLegalReference(card,event);
    $('security-events').append(card);
  }
  if(!more&&!result.events.length)$('security-events').textContent='Событий пока нет. Журнал начинает собираться после обновления.';
  securityNext=result.next;$('security-more').hidden=!securityNext;
  developerBinding=result.developerCertificate;ownerCertificates=result.ownerCertificates;
  $('developer-binding').textContent=developerBinding?'Закреплён: '+developerBinding.certificate+' · '+developerBinding.product+' · '+developerBinding.player:'Ещё не закреплён. Войди владельцем из игры или выбери свой зарегистрированный сертификат ниже.';
  const select=$('owner-certificate');const current=select.value;select.replaceChildren();
  for(const c of ownerCertificates){const option=document.createElement('option');option.value=c.id;option.textContent=c.id+' · '+c.product;select.append(option);}
  if(ownerCertificates.some(c=>c.id===current))select.value=current;else if(developerBinding)select.value=developerBinding.certificate;
  $('save-binding').disabled=ownerCertificates.length===0;
}
$('security-refresh').addEventListener('click',()=>action($('security-refresh'),()=>loadSecurity()));
$('security-more').addEventListener('click',()=>action($('security-more'),()=>loadSecurity(true)));
$('logout-others').addEventListener('click',()=>action($('logout-others'),async()=>{await api('/api/moderation/logout-others',{});$('status').textContent='Остальные сеансы кабинета завершены.';await loadSecurity();}));
$('binding-form').addEventListener('submit',event=>{event.preventDefault();action($('save-binding'),async()=>{
  const selected=ownerCertificates.find(c=>c.id===$('owner-certificate').value);if(!selected)throw Error('Выбери зарегистрированный сертификат.');
  const password=$('owner-password').value;$('owner-password').value='';
  await api('/api/moderation/developer-certificate',{certificateId:selected.id,productId:selected.product,previousCertificateId:developerBinding?developerBinding.certificate:'',password});
  $('status').textContent='Единственный сертификат разработчика закреплён.';await loadSecurity();
});});
