const base = new URL(document.currentScript.src).pathname.replace(/\/app\.js$/, "");
const el = id => document.getElementById(id);
let csrf = "", busy = false, poll;
const messages = {
  logged_in: "企业登录已完成。下一步，授权本应用访问你的基本信息。",
  working: "正在调用中国区 Runtime 与 Identity。首次启动可能需要约一分钟。",
  authorization_ready: "授权链接已准备好。点击“继续至 Entra”，并使用刚才登录的同一个企业账户。",
  binding: "正在验证当前浏览器会话，并完成 Identity 授权绑定。",
  authorized: "Identity 授权绑定已完成。现在可以运行 MCP 工具验证。",
  complete: "验证完成：原生 Identity 获取令牌，Graph 返回 HTTP 200，且用户一致。",
  failed: "本次操作未完成。请下载结果文件，查看具体阶段和响应。",
};
function status(text, mode="") { el("status").textContent=text; el("status").parentElement.className="status-line "+mode; }
function show(id, visible) { el(id).classList.toggle("hidden", !visible); }
async function refresh() {
  clearTimeout(poll);
  try {
    const r=await fetch(base+"/api/session", {cache:"no-store"});
    if(r.status===401) {
      csrf="";el("session-label").textContent="未登录";
      status("请使用企业账户开始登录；设备要求由本次适用的组织策略决定。会话有效期最长 15 分钟。");
      show("login",true);show("logout",false);show("continue",false);show("authorize",true);show("result-panel",false);
      el("authorize").disabled=true;el("run").disabled=true;
      ["step-login","step-auth","step-check"].forEach(id=>el(id).classList.remove("done"));
      return;
    }
    if(!r.ok)throw Error("服务暂时不可用（HTTP "+r.status+"）。");
    const s=await r.json();csrf=s.csrf;
    el("session-label").textContent="企业会话已建立 · "+new Date(s.expires_at*1000).toLocaleTimeString("zh-CN",{hour:"2-digit",minute:"2-digit"})+" 到期";
    show("login",false);show("logout",true);
    el("step-login").classList.add("done");
    const waiting=["working","binding"].includes(s.phase);
    el("step-auth").classList.toggle("done",["authorized","complete"].includes(s.phase));
    el("step-check").classList.toggle("done",s.phase==="complete");
    el("authorize").disabled=waiting;show("authorize",s.phase!=="authorization_ready");
    show("continue",s.phase==="authorization_ready");
    el("run").disabled=waiting||!["authorized","complete","failed"].includes(s.phase);
    if(s.phase==="failed")el("run").disabled=!s.report?.session_binding;
    status(messages[s.phase]||"正在读取状态。",waiting?"busy":s.phase==="failed"?"error":"");
    show("result-panel",!!s.report&&!waiting);
    if(s.report) {
      el("result-title").textContent=s.report.status==="passed"?"验证完成":"本次操作结果";
      el("graph-status").textContent=s.report.graph?.http_status??"未调用";
      el("user-match").textContent=s.report.graph?.same_user_as_verified_token_a===true?"同一用户":"尚未确认";
      el("native-used").textContent=s.report.identity_access_token_received===true?"已获取令牌":"尚未完成";
      el("evidence").textContent=JSON.stringify(s.report,null,2);
    }
    poll=setTimeout(refresh,waiting?4000:30000);
  } catch(e) { status(e.message+" 请刷新页面重试。","error"); }
}
async function post(path) {
  if(busy)return;busy=true;
  try {
    const r=await fetch(base+path,{method:"POST",headers:{"X-CSRF-Token":csrf}});
    if(!r.ok) {const data=await r.json();throw Error("操作未完成："+(data.error||r.status));}
    await refresh();
  } catch(e){status(e.message,"error");}finally{busy=false;}
}
el("authorize").addEventListener("click",()=>post("/authorize"));
el("run").addEventListener("click",()=>post("/run"));
el("logout").addEventListener("click",()=>post("/logout"));
refresh();
