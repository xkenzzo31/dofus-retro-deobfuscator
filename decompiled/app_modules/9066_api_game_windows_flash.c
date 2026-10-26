/* 9066 [lit 124, 3 args] <- anonymous_51 */
undefined4 9066(undefined4 receiver,int a0,undefined4 a1,undefined4 a2)
{
  CreateFunctionContext(scope_9066);
  iVar1 = Call(a2,0x2518);
  _0x4a2f65 = iVar1.app;
  _0x5d145b = iVar1.screen;
  _0x1bc6fb = iVar1.BrowserWindow;
  _0x143b0b = Call(a2,0x3f9);
  _0x5ab849 = Call(a2,0xe5e);
  _0x5ed84b = Call(a2,0x1d66);
  Call(a2,0xabf);
  uVar2 = CreateClosure(anonymous_126);
  a0.exports.init = uVar2;
  a0.exports.newWindow = _0x46fcf4;
  uVar2 = CreateClosure(anonymous_138);
  a0.exports.retroChatOpen = uVar2;
  uVar2 = CreateClosure(anonymous_166);
  a0.exports.retroConsoleOpen = uVar2;
  uVar2 = CreateClosure(anonymous_191);
  a0.exports.setLoginDiscordActivity = uVar2;
  uVar2 = CreateClosure(anonymous_197);
  a0.exports.setIngameDiscordActivity = uVar2;
  uVar2 = CreateClosure(anonymous_203);
  a0.exports.applyHighResolutionOption = uVar2;
  uVar2 = CreateClosure(anonymous_214);
  a0.exports.setLanguage = uVar2;
  a0.exports.isGameApiInitialized = _0x348e47;
  uVar2 = CreateClosure(anonymous_220);
  a0.exports.setGameApiInitialized = uVar2;
  uVar2 = CreateClosure(anonymous_226);
  a0.exports.setOption = uVar2;
  _0x19f929 = false;
  _0x348e47 = false;
  uVar2 = CreateClosure(anonymous_279);
  Call(setImmediate,uVar2);
  uVar2 = CreateClosure(anonymous_285);
  a0.exports.reloadRetroChats = uVar2;
  return undefined;
}
/* _0x348e47 [lit 240, 0 args] <- 9066 */
undefined4 _0x348e47(undefined4 receiver)
{
  CreateFunctionContext(scope__0x348e47);
  return _0x348e47;
}
/* _0x46fcf4 [lit 247, 0 args] <- 9066 */
undefined4 _0x46fcf4(undefined4 receiver)
{
  CreateFunctionContext(scope__0x46fcf4);
  CreateBlockContext(block_scope__0x46fcf4);
  _0x5286de = the_hole;
  if (_0x19f929 != 0) {
    iVar1 = CreateEmptyObjectLiteral();
    iVar1.nodeIntegration = true;
    iVar1.plugins = true;
    iVar1.backgroundThrottling = false;
    iVar1.spellcheck = false;
    iVar1.affinity = "game";
    iVar1.enableRemoteModule = true;
    iVar1.contextIsolation = false;
    iVar1.webviewTag = true;
    iVar2 = CreateEmptyObjectLiteral();
    iVar2.width = 0x2e6;
    iVar2.height = 0x22c;
    iVar2.useContentSize = true;
    iVar2.backgroundColor = "#000000";
    iVar2.webPreferences = iVar1;
    iVar1 = Construct(_0x1bc6fb,iVar2);
    _0x5286de = iVar1.webContents;
    iVar2 = _0x5286de.session;
    CallProperty(iVar2.setSpellCheckerDictionaryDownloadURL,iVar2,"https://00.00/");
    if (process.defaultApp == 0) {
      CallProperty(iVar1.setMenu,iVar1,null);
    }
    uVar3 = CreateClosure(anonymous_253);
    CallProperty(iVar1.on,iVar1,"close",uVar3);
    uVar3 = CreateClosure(anonymous_259);
    CallProperty(iVar1.on,iVar1,"closed",uVar3);
    uVar3 = CreateClosure(anonymous_265);
    CallProperty(iVar1.on,iVar1,"focus",uVar3);
    uVar3 = CreateClosure(anonymous_273);
    CallProperty(iVar1.on,iVar1,"blur",uVar3);
    CallProperty(iVar1.loadURL,iVar1,"file://" + __dirname + "/retroclient/D1ElectronLauncher.html")
    ;
    api.gameWindow = iVar1;
    return undefined;
  }
  return undefined;
}
/* anonymous_253 [lit 253, 1 args] <- _0x46fcf4 */
undefined4 anonymous_253(undefined4 receiver,int a0)
{
  CreateFunctionContext(scope_anonymous_253);
  iVar1 = api.eventClient;
  iVar1 = CallProperty(iVar1.hasEventToSend,iVar1);
  if (iVar1 != 0) {
    CallProperty(a0.preventDefault,a0);
    iVar1 = api.eventClient;
    CallProperty(iVar1.onFlush,iVar1,true);
  }
  return undefined;
}
/* anonymous_259 [lit 259, 0 args] <- _0x46fcf4 */
undefined4 anonymous_259(undefined4 receiver)
{
  CreateFunctionContext(scope_anonymous_259);
  cVar1 = IsUndetectable(api.chatWindow);
  if ((cVar1 == '\0') &&
     (iVar2 = api.chatWindow, iVar2 = CallProperty(iVar2.isDestroyed,iVar2), iVar2 == 0)) {
    iVar2 = api.chatWindow;
    CallProperty(iVar2.close,iVar2);
  }
  if (((process.defaultApp != 0) && (cVar1 = IsUndetectable(api.consoleWindow), cVar1 == '\0')) &&
     (iVar2 = api.consoleWindow, iVar2 = CallProperty(iVar2.isDestroyed,iVar2), iVar2 == 0)) {
    iVar2 = api.consoleWindow;
    CallProperty(iVar2.close,iVar2);
  }
  return undefined;
}
/* anonymous_265 [lit 265, 0 args] <- _0x46fcf4 */
undefined4 anonymous_265(undefined4 receiver)
{
  CreateFunctionContext(scope_anonymous_265);
  CallProperty(_0x5286de.send,_0x5286de,"onWindowFocused");
  return undefined;
}
/* anonymous_273 [lit 273, 0 args] <- _0x46fcf4 */
undefined4 anonymous_273(undefined4 receiver)
{
  CreateFunctionContext(scope_anonymous_273);
  CallProperty(_0x5286de.send,_0x5286de,"onWindowBlurried");
  return undefined;
}
/* anonymous_126 [lit 126, 0 args] <- 9066 */
undefined4 anonymous_126(undefined4 receiver)
{
  CreateFunctionContext(scope_anonymous_126);
  if (_0x19f929 == 0) {
    iVar1 = api.menu;
    CallProperty(iVar1.setApplicationMenu,iVar1);
    uVar2 = CallProperty(_0x4a2f65.getPath,_0x4a2f65,"userData");
    uVar3 = CallProperty(_0x143b0b.join,_0x143b0b,uVar2,"Pepper Data");
    uVar4 = CallProperty(_0x143b0b.join,_0x143b0b,uVar3,"Shockwave Flash");
    uVar5 = CallProperty(_0x143b0b.join,_0x143b0b,uVar4,"System");
    uVar6 = CallProperty(_0x143b0b.join,_0x143b0b,uVar4,"WritableRoot");
    iVar1 = api.utils;
    CallProperty(iVar1.createDir,iVar1,uVar2);
    iVar1 = api.utils;
    CallProperty(iVar1.createDir,iVar1,uVar3);
    iVar1 = api.utils;
    CallProperty(iVar1.createDir,iVar1,uVar4);
    iVar1 = api.utils;
    CallProperty(iVar1.createDir,iVar1,uVar5);
    uVar2 = CallProperty(_0x143b0b.join,_0x143b0b,uVar5,"mms.cfg");
    iVar1 = api.utils;
    uVar3 = CallProperty(_0x143b0b.join,_0x143b0b,__dirname,"mms.cfg");
    CallProperty(iVar1.copyFile,iVar1,uVar3,uVar2);
    iVar1 = CallProperty(_0x4a2f65.getName,_0x4a2f65);
    uVar2 = CallProperty(iVar1.replace,iVar1," ","");
    iVar1 = CallProperty(_0x5ab849.initSync,_0x5ab849,uVar2,uVar6);
    CallProperty(iVar1.empty,iVar1);
    iVar7 = CallProperty(_0x143b0b.join,_0x143b0b,__dirname,"retroclient");
    CallProperty(iVar1.add,iVar1,"\uxfeff" + iVar7);
    _0x19f929 = true;
    Call(_0x46fcf4);
  }
  return undefined;
}
/* anonymous_138 [lit 138, 0 args] <- 9066 */
undefined4 anonymous_138(undefined4 receiver)
{
  CreateFunctionContext(scope_anonymous_138);
  CreateBlockContext(block_scope_anonymous_138);
  _0xfee81d = the_hole;
  if (_0x19f929 == 0) {
    return undefined;
  }
  cVar1 = IsUndetectable(api.chatWindow);
  if ((cVar1 == '\0') &&
     (iVar2 = api.chatWindow, iVar2 = CallProperty(iVar2.isDestroyed,iVar2), iVar2 == 0)) {
    return undefined;
  }
  iVar2 = CreateEmptyObjectLiteral();
  iVar2.nodeIntegration = true;
  iVar2.plugins = false;
  iVar2.backgroundThrottling = false;
  iVar2.spellcheck = false;
  iVar2.affinity = "chat";
  iVar2.enableRemoteModule = true;
  iVar2.contextIsolation = false;
  uVar6 = _0x1bc6fb;
  iVar3 = CallProperty(_0x5d145b.getPrimaryDisplay,_0x5d145b);
  iVar4 = iVar3.bounds.height;
  iVar5 = CreateObjectLiteral({x, y, width, height, useContentSize, webPreferences});
  iVar5.x = iVar3.bounds.width + -0x2e6;
  iVar5.y = iVar4 / 2 + -0x116;
  iVar5.webPreferences = iVar2;
  iVar2 = Construct(uVar6,iVar5);
  CallProperty(iVar2.setAutoHideMenuBar,iVar2,true);
  _0xfee81d = iVar2.webContents;
  uVar6 = CreateClosure(anonymous_144);
  CallProperty(_0xfee81d.on,_0xfee81d,"did-finish-load",uVar6);
  uVar6 = CreateClosure(anonymous_150);
  CallProperty(_0xfee81d.on,_0xfee81d,"found-in-page",uVar6);
  CallProperty(iVar2.loadURL,iVar2,"file://" + __dirname + "/retroclient/D1Chat.html");
  api.chatWindow = iVar2;
  return undefined;
}
/* anonymous_144 [lit 144, 0 args] <- anonymous_138 */
undefined4 anonymous_144(undefined4 receiver)
{
  CreateFunctionContext(scope_anonymous_144);
  CallProperty(_0xfee81d.setZoomFactor,_0xfee81d,1);
  CallProperty(_0xfee81d.setVisualZoomLevelLimits,_0xfee81d,1,3);
  return undefined;
}
/* anonymous_150 [lit 150, 0 args] <- anonymous_138 */
undefined4 anonymous_150(undefined4 receiver)
{
  CreateFunctionContext(scope_anonymous_150);
  CallProperty(_0xfee81d.send,_0xfee81d,"focusSearch");
  return undefined;
}
/* anonymous_166 [lit 166, 0 args] <- 9066 */
undefined4 anonymous_166(undefined4 receiver)
{
  CreateFunctionContext(scope_anonymous_166);
  CreateBlockContext(block_scope_anonymous_166);
  _0x38c5c7 = the_hole;
  if (_0x19f929 == 0) {
    return undefined;
  }
  cVar1 = IsUndetectable(api.consoleWindow);
  if ((cVar1 == '\0') &&
     (iVar2 = api.consoleWindow, iVar2 = CallProperty(iVar2.isDestroyed,iVar2), iVar2 == 0)) {
    return undefined;
  }
  iVar2 = CreateEmptyObjectLiteral();
  iVar2.nodeIntegration = true;
  iVar2.plugins = false;
  iVar2.backgroundThrottling = false;
  iVar2.spellcheck = false;
  iVar2.affinity = "console";
  iVar2.enableRemoteModule = true;
  iVar2.contextIsolation = false;
  uVar6 = _0x1bc6fb;
  iVar3 = CallProperty(_0x5d145b.getPrimaryDisplay,_0x5d145b);
  iVar4 = iVar3.bounds.height;
  iVar5 = CreateObjectLiteral({x, y, width, height, useContentSize, webPreferences});
  iVar5.x = iVar3.bounds.width + -0x2e6;
  iVar5.y = iVar4 / 2 + -0x116;
  iVar5.webPreferences = iVar2;
  iVar2 = Construct(uVar6,iVar5);
  CallProperty(iVar2.setAutoHideMenuBar,iVar2,true);
  _0x38c5c7 = iVar2.webContents;
  uVar6 = CreateClosure(anonymous_172);
  CallProperty(_0x38c5c7.on,_0x38c5c7,"did-finish-load",uVar6);
  uVar6 = CreateClosure(anonymous_178);
  CallProperty(_0x38c5c7.on,_0x38c5c7,"found-in-page",uVar6);
  CallProperty(iVar2.loadURL,iVar2,"file://" + __dirname + "/retroclient/D1Console.html");
  api.consoleWindow = iVar2;
  return undefined;
}
/* anonymous_172 [lit 172, 0 args] <- anonymous_166 */
undefined4 anonymous_172(undefined4 receiver)
{
  CreateFunctionContext(scope_anonymous_172);
  CallProperty(_0x38c5c7.setZoomFactor,_0x38c5c7,1);
  CallProperty(_0x38c5c7.setVisualZoomLevelLimits,_0x38c5c7,1,3);
  return undefined;
}
/* anonymous_178 [lit 178, 0 args] <- anonymous_166 */
undefined4 anonymous_178(undefined4 receiver)
{
  CreateFunctionContext(scope_anonymous_178);
  CallProperty(_0x38c5c7.send,_0x38c5c7,"focusSearch");
  return undefined;
}
/* anonymous_191 [lit 191, 2 args] <- 9066 */
undefined4 anonymous_191(undefined4 receiver,undefined4 a0,undefined4 a1)
{
  CreateFunctionContext(scope_anonymous_191);
  iVar2 = api.config;
  iVar2 = CallProperty(iVar2.get,iVar2,"bDiscordIntegration");
  if (iVar2 != 0) {
    iVar2 = api.discordRpc;
    iVar3 = CreateEmptyObjectLiteral();
    iVar3.state = "Login";
    iVar3.largeImageKey = "icon";
    iVar3.largeImageText = "Dofus Retro";
    if (iVar2 != 0) {
      cVar1 = IsUndetectable(a0);
      if (cVar1 == '\0') {
        uVar4 = iVar2.setActivity;
        iVar3 = CreateObjectLiteral({state, details, largeImageKey, largeImageText});
        iVar3.state = "Login";
        iVar3.details = a0;
        iVar3.largeImageKey = "icon";
        iVar3.largeImageText = "Dofus Retro";
        CallProperty(uVar4,iVar2,iVar3);
      }
      else {
        CallProperty(iVar2.setActivity,iVar2,iVar3);
      }
    }
  }
  return undefined;
}
/* anonymous_197 [lit 197, 7 args] <- 9066 */
undefined4
anonymous_197(undefined4 receiver,undefined4 a0,undefined4 a1,int a2,int a3,undefined4 a4,int a5,
             int a6)
{
  CreateFunctionContext(scope_anonymous_197);
  iVar2 = api.config;
  iVar2 = CallProperty(iVar2.get,iVar2,"bDiscordIntegration");
  if ((((iVar2 != 0) && (iVar2 = api.discordRpc, iVar2 != 0)) && (process.defaultApp == 0)) &&
     ((iVar3 = CallProperty(a3.includes,a3,"["), iVar3 == 0 &&
      (iVar3 = CallProperty(a3.includes,a3,"]"), iVar3 == 0)))) {
    pcVar4 = "icon";
    iVar3 = a5 * 10 + a6;
    uVar7 = 0xffffffff;
    if ((((iVar3 == 10) || ((iVar3 == 0x15 || (iVar3 == 0x1e)))) ||
        ((iVar3 == 0x1f || (((iVar3 == 0x32 || (iVar3 == 0x33)) || (iVar3 == 0x3c)))))) ||
       (((((iVar3 == 0x3d || (iVar3 == 0x46)) ||
          ((iVar3 == 0x47 || ((iVar3 == 0x51 || (iVar3 == 0x5a)))))) || (iVar3 == 0x5b)) ||
        ((iVar3 == 0x65 || (iVar3 == 0x6f)))))) {
      uVar7 = 4;
    }
    else if ((((iVar3 == 0xb) || (iVar3 == 0x14)) || (iVar3 == 0x28)) || (iVar3 == 0x29)) {
      uVar7 = 3;
    }
    else if (((iVar3 == 0x50) || (iVar3 == 100)) || (iVar3 == 0x6e)) {
      uVar7 = 5;
    }
    else if ((iVar3 == 0x78) || (iVar3 == 0x79)) {
      uVar7 = 1;
    }
    cVar1 = LooseEquals(0xffffffff,uVar7);
    if (cVar1 == '\0') {
      iVar5 = api.utils;
      iVar5 = CallProperty(iVar5.randomInt,iVar5,1,uVar7);
      pcVar4 = "gfx" + iVar3 + "-" + iVar5;
    }
    uVar7 = iVar2.setActivity;
    iVar3 = CreateObjectLiteral(
                               {state, details, largeImageKey, largeImageText, smallImageKey, smallImageText, ...}
    iVar3.state = a1;
    iVar3.details = " (" + a3 + a2 + ")";
    iVar3.largeImageKey = pcVar4;
    iVar3.largeImageText = a4;
    iVar3.smallImageKey = "icon";
    iVar3.smallImageText = a0;
    uVar6 = CallProperty(Date.now,Date);
    iVar3.startTimestamp = uVar6;
    CallProperty(uVar7,iVar2,iVar3);
  }
  return undefined;
}
/* anonymous_203 [lit 203, 1 args] <- 9066 */
undefined4 anonymous_203(undefined4 receiver,int a0)
{
  CreateFunctionContext(scope_anonymous_203);
  if ("win32" == process.platform) {
    uVar1 = CallProperty(_0x4a2f65.getPath,_0x4a2f65,"exe");
    iVar2 = CreateEmptyObjectLiteral();
    if (a0 == 0) {
      pcVar3 = "~ DPIUNAWARE";
    }
    else {
      pcVar3 = "~ HIGHDPIAWARE";
    }
    iVar2.value = pcVar3;
    iVar2.type = "REG_SZ";
    uVar4 = CreateEmptyObjectLiteral();
    SetProperty(uVar4,uVar1,iVar2);
    iVar2 = CreateEmptyObjectLiteral();
    iVar2.["HKCU\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers"] = uVar4;
    uVar1 = CreateClosure(anonymous_209);
    CallProperty(_0x5ed84b.putValue,_0x5ed84b,iVar2,uVar1);
  }
  else {
    CallProperty(console.log,console,"Unsupported platform for applyHighResolutionOption");
  }
  return undefined;
}
/* anonymous_209 [lit 209, 1 args] <- anonymous_203 */
undefined4 anonymous_209(undefined4 receiver,undefined4 a0)
{
  CreateFunctionContext(scope_anonymous_209);
  cVar1 = IsUndetectable(a0);
  if (cVar1 == '\0') {
    CallProperty(console.log,console,a0);
  }
  return undefined;
}
/* anonymous_214 [lit 214, 1 args] <- 9066 */
undefined4 anonymous_214(undefined4 receiver,undefined4 a0)
{
  CreateFunctionContext(scope_anonymous_214);
  iVar1 = api.config;
  CallProperty(iVar1.set,iVar1,"sCurrentLanguage",a0);
  iVar1 = api.game;
  CallProperty(iVar1.reloadRetroChats,iVar1);
  return undefined;
}
/* anonymous_220 [lit 220, 0 args] <- 9066 */
undefined4 anonymous_220(undefined4 receiver)
{
  CreateFunctionContext(scope_anonymous_220);
  _0x348e47 = true;
  return undefined;
}
/* anonymous_226 [lit 226, 2 args] <- 9066 */
undefined4 anonymous_226(undefined4 receiver,char[] a0,undefined4 a1)
{
  CreateFunctionContext(scope_anonymous_226);
  if (a0 == "ElectronBackgroundNotifications") {
    iVar2 = api.config;
    CallProperty(iVar2.set,iVar2,"bBackgroundNotifications",a1);
  }
  else if (a0 == "ElectronDiscordRichPresence") {
    iVar2 = api.config;
    CallProperty(iVar2.set,iVar2,"bDiscordIntegration",a1);
  }
  else if (a0 == "ElectronEnableForceGPURendering") {
    iVar2 = api.config;
    CallProperty(iVar2.set,iVar2,"bForceGPURendering",a1);
  }
  else if (a0 == "ElectronEnableHighRes") {
    iVar2 = api.game;
    CallProperty(iVar2.applyHighResolutionOption,iVar2,a1);
  }
  else if (a0 == "ElectronEnableChatDarkMode") {
    iVar2 = api.config;
    CallProperty(iVar2.set,iVar2,"bChatDarkMode",a1);
    iVar2 = api.game;
    CallProperty(iVar2.reloadRetroChats,iVar2);
  }
  else if (a0 == "ElectronEnableLimitWidescreenPanelWidth") {
    iVar2 = api.config;
    CallProperty(iVar2.set,iVar2,"bLimitWidescreenPanelWidth",a1);
    cVar1 = IsUndetectable(api.gameWindow);
    if ((cVar1 == '\0') &&
       (iVar2 = api.gameWindow, iVar2 = CallProperty(iVar2.isDestroyed,iVar2), iVar2 == 0)) {
      iVar2 = api.gameWindow.webContents;
      CallProperty(iVar2.send,iVar2,"arrangeElements");
    }
  }
  return undefined;
}
/* anonymous_279 [lit 279, 0 args] <- 9066 */
undefined4 anonymous_279(undefined4 receiver)
{
  CreateFunctionContext(scope_anonymous_279);
  uVar1 = CallProperty(_0x143b0b.join,_0x143b0b,sWritableRootFolderPath,"#SharedObjects/");
  iVar2 = api.utils;
  iVar2 = CallProperty(iVar2.getDirectories,iVar2,uVar1);
  if ((iVar2 != undefined) && (iVar2 != null)) {
    uVar5 = ToObject(iVar2);
    uVar1 = ForInEnumerate(uVar5);
    uVar6 = ForInPrepare(uVar1,0);
    uVar7 = ForInPrepare(uVar1,1);
    iVar8 = ForInPrepare(uVar1,2);
    for (iVar9 = 0; iVar9 < iVar8; iVar9 = iVar9 + 1) {
      iVar3 = ForInNext(uVar5,iVar9,uVar6,uVar7);
      if (iVar3 != undefined) {
        uVar1 = GetProperty(iVar2,iVar3);
        uVar1 = CallProperty(_0x143b0b.join,_0x143b0b,uVar1,
                             "macromedia.com/support/flashplayer/sys/#local/settings.sol");
        iVar3 = api.utils;
        uVar4 = CallProperty(_0x143b0b.join,_0x143b0b,__dirname,"flashsettingslocalhost.sol");
        CallProperty(iVar3.copyFile,iVar3,uVar4,uVar1);
      }
    }
  }
  return undefined;
}
/* anonymous_285 [lit 285, 0 args] <- 9066 */
undefined4 anonymous_285(undefined4 receiver)
{
  CreateFunctionContext(scope_anonymous_285);
  cVar1 = IsUndetectable(api.gameWindow);
  if ((cVar1 == '\0') &&
     (iVar2 = api.gameWindow, iVar2 = CallProperty(iVar2.isDestroyed,iVar2), iVar2 == 0)) {
    iVar2 = api.gameWindow.webContents;
    CallProperty(iVar2.send,iVar2,"reloadChatWebView");
  }
  cVar1 = IsUndetectable(api.chatWindow);
  if ((cVar1 == '\0') &&
     (iVar2 = api.chatWindow, iVar2 = CallProperty(iVar2.isDestroyed,iVar2), iVar2 == 0)) {
    iVar2 = api.chatWindow;
    CallProperty(iVar2.reload,iVar2);
  }
  return undefined;
}
