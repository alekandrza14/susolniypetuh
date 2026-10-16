"use strict";
(() => {
  const phoneForm=document.getElementById('phone-form'), codeForm=document.getElementById('code-form');
  const status=document.getElementById('status'), send=document.getElementById('send'), check=document.getElementById('check');
  const ownerForm=document.getElementById('owner-form'),ownerCheck=document.getElementById('owner-check');
  const match=/^#([a-f0-9]{32})\.([A-Za-z0-9_-]{32,128})$/.exec(location.hash);
  // Keep the browser token out of URLs, referrers, history and local storage.
  history.replaceState(null,'',location.pathname);
  if(!match){phoneForm.hidden=true;status.textContent='Начни проверку через кнопку загрузки сертификата в игре.';return;}
  const [,session,token]=match;
  async function request(action,data){
    const response=await fetch('/api/sessions/'+session+'/'+action,{method:'POST',headers:{'Content-Type':'application/json','Authorization':'Bearer '+token},body:JSON.stringify({...data,device:window.MyEngineDevice.read()}),credentials:'omit',redirect:'error',cache:'no-store'});
    const result=await response.json();
    if(!response.ok)throw new Error(result.error||'Не удалось выполнить проверку');
    return result;
  }
  phoneForm.addEventListener('submit',async event=>{
    event.preventDefault();if(send.disabled)return;
    const number=document.getElementById('phone').value.trim();
    if(!/^\+[1-9][0-9]{7,14}$/.test(number)){status.textContent='Укажи международный номер, например +371… или +7…, без пробелов.';return;}
    send.disabled=true;status.textContent='Проверяем запись игрока и отправляем SMS…';
    try{
      const result=await request('phone',{phone:number});
      if(!['sent','queued','owner_password'].includes(result.status))throw new Error('Неизвестный ответ сервера');
      phoneForm.hidden=true;document.getElementById('phone').value='';
      if(result.status==='owner_password'){
        ownerForm.hidden=false;status.textContent='Аккаунт владельца. Введи пароль — SMS не требуется.';document.getElementById('password').focus();
      }else{
        codeForm.hidden=false;status.textContent=result.status==='queued'?'Код поставлен в очередь на телефоне отправителя. Дождись SMS и введи код.':'SMS отправлена. Введи код.';document.getElementById('code').focus();
      }
    }
    catch(error){status.textContent=error.message;send.disabled=false;}
  });
  ownerForm.addEventListener('submit',async event=>{
    event.preventDefault();if(ownerCheck.disabled)return;
    ownerCheck.disabled=true;status.textContent='Проверяем пароль…';
    const input=document.getElementById('password');
    try{
      const result=await request('owner-password',{password:input.value});
      if(result.status!=='verified')throw new Error('Вход не подтверждён');
      input.value='';ownerForm.hidden=true;status.textContent='Владелец подтверждён. Вернись в игру и нажми кнопку входа.';
    }catch(error){input.value='';status.textContent=error.message;ownerCheck.disabled=false;}
  });
  codeForm.addEventListener('submit',async event=>{
    event.preventDefault();if(check.disabled)return;
    check.disabled=true;status.textContent='Проверяем код…';
    const input=document.getElementById('code');
    try{await request('code',{code:input.value.trim()});input.value='';codeForm.hidden=true;status.textContent='Игрок подтверждён. Вернись в игру — доступ обновится автоматически.';}
    catch(error){input.value='';status.textContent=error.message;check.disabled=false;}
  });
})();
