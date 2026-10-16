'use strict';
// An origin-local random browser label, not a hardware fingerprint or credential.
window.MyEngineDevice=(()=>{
  let id='',name='';
  try{id=localStorage.getItem('myengine-browser-id')||'';name=localStorage.getItem('myengine-device-name')||'';}catch{}
  if(!/^[a-f0-9]{32}$/.test(id)){
    const bytes=new Uint8Array(16);crypto.getRandomValues(bytes);id=Array.from(bytes,b=>b.toString(16).padStart(2,'0')).join('');
    try{localStorage.setItem('myengine-browser-id',id);}catch{}
  }
  const field=document.getElementById('device-name');if(field)field.value=name.slice(0,80);
  return {read(){
    name=field?field.value.trim().slice(0,80):name;
    try{localStorage.setItem('myengine-device-name',name);}catch{}
    return {id,name};
  }};
})();
