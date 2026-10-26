/* 7318 [lit 53, 3 args] <- anonymous_51 */
undefined4 7318(undefined4 receiver,int a0,undefined4 a1,undefined4 a2)
{
  CreateFunctionContext(scope_7318);
  CreateBlockContext(block_scope_7318);
  iVar1 = Call(a2,0x2518);
  _0xbb8866 = iVar1.app;
  _0x447ce6 = Call(a2,0x979);
  _0x3ca30d = Call(a2,0x3f9);
  iVar1 = Call(a2,0x3be);
  _0x2726ae = iVar1.ElectronJSONSettingsStoreMain;
  _0x3817cc = Call(a2,0xd23);
  uVar2 = CreateClosure(anonymous_59);
  _0x80a9ee = a2;
  a0.exports.init = uVar2;
  uVar2 = CreateClosure(anonymous_65);
  a0.exports.initOnReady = uVar2;
  return undefined;
}
/* anonymous_59 [lit 59, 0 args] <- 7318 */
undefined4 anonymous_59(undefined4 receiver)
{
  CreateFunctionContext(scope_anonymous_59);
  iVar2 = CreateEmptyObjectLiteral();
  iVar2.["fr-CA"] = "fr";
  iVar2.["fr-CH"] = "fr";
  iVar2.["fr-FR"] = "fr";
  iVar2.["de-AT"] = "de";
  iVar2.["de-CH"] = "de";
  iVar2.["de-DE"] = "de";
  iVar2.["es-419"] = "es";
  iVar2.["it-CH"] = "it";
  iVar2.["it-IT"] = "it";
  iVar2.["pt-BR"] = "pt";
  iVar2.["pt-PT"] = "pt";
  iVar3 = CreateEmptyObjectLiteral();
  iVar3.__ = "translate";
  iVar3.__n = "translateplural";
  iVar4 = CreateEmptyObjectLiteral();
  iVar4.default = true;
  iVar4.type = "boolean";
  iVar5 = CreateEmptyObjectLiteral();
  iVar5.default = true;
  iVar5.type = "boolean";
  iVar6 = CreateEmptyObjectLiteral();
  iVar6.default = true;
  iVar6.type = "boolean";
  iVar7 = CreateEmptyObjectLiteral();
  iVar7.default = "";
  iVar7.type = "string";
  iVar8 = CreateEmptyObjectLiteral();
  iVar8.default = false;
  iVar8.type = "boolean";
  iVar9 = CreateEmptyObjectLiteral();
  iVar9.default = false;
  iVar9.type = "boolean";
  iVar10 = CreateEmptyObjectLiteral();
  iVar10.default = 0x23;
  iVar10.type = "number";
  iVar11 = CreateEmptyObjectLiteral();
  iVar11.default = 0x10;
  iVar11.type = "number";
  iVar12 = CreateEmptyObjectLiteral();
  iVar12.default = 0x10;
  iVar12.type = "number";
  iVar13 = CreateEmptyObjectLiteral();
  iVar13.default = true;
  iVar13.type = "boolean";
  iVar14 = CreateEmptyObjectLiteral();
  iVar14.bBackgroundNotifications = iVar4;
  iVar14.bDiscordIntegration = iVar5;
  iVar14.bForceGPURendering = iVar6;
  iVar14.sCurrentLanguage = iVar7;
  iVar14.bChatDarkMode = iVar8;
  iVar14.bPanelRightSide = iVar9;
  iVar14.nInfosContentSize = iVar10;
  iVar14.nRetroChatTextSize = iVar11;
  iVar14.nRetroConsoleTextSize = iVar12;
  iVar14.bLimitWidescreenPanelWidth = iVar13;
  iVar5 = CreateEmptyObjectLiteral();
  iVar5.watchFile = false;
  iVar5.writeBeforeQuit = true;
  iVar6 = CreateEmptyObjectLiteral();
  iVar6.transport = "ipc";
  iVar7 = CreateEmptyObjectLiteral();
  iVar7.clientId = "1243223580138012815";
  uVar15 = Construct(Object);
  _0x80a9ee.g.api = uVar15;
  uVar15 = Construct(Object);
  api.i18n = uVar15;
  iVar4 = _0x447ce6;
  uVar15 = _0x447ce6.configure;
  iVar8 = CreateObjectLiteral({locales, fallbacks, register, directory, api});
  iVar8.fallbacks = iVar2;
  iVar8.register = api.i18n;
  uVar16 = CallProperty(_0x3ca30d.join,_0x3ca30d,__dirname,"/locales");
  iVar8.directory = uVar16;
  iVar8.api = iVar3;
  CallProperty(uVar15,iVar4,iVar8);
  iVar4 = Construct(_0x2726ae,iVar14,iVar5);
  CallProperty(iVar4.initSync,iVar4);
  iVar2 = CallProperty(iVar4.get,iVar4,"bForceGPURendering");
  if (iVar2 != 0) {
    iVar2 = _0xbb8866.commandLine;
    CallProperty(iVar2.appendSwitch,iVar2,"ignore-gpu-blacklist");
    iVar2 = _0xbb8866.commandLine;
    CallProperty(iVar2.appendSwitch,iVar2,"enable-gpu-rasterization");
    iVar2 = _0xbb8866.commandLine;
    CallProperty(iVar2.appendSwitch,iVar2,"enable-oop-rasterization");
    iVar2 = _0xbb8866.commandLine;
    CallProperty(iVar2.appendSwitch,iVar2,"enable-zero-copy");
  }
  api.config = iVar4;
  uVar15 = Call(_0x80a9ee,0x236a);
  api.game = uVar15;
  uVar15 = Call(_0x80a9ee,0x10c0);
  api.utils = uVar15;
  uVar15 = Call(_0x80a9ee,0x196);
  api.security = uVar15;
  uVar15 = Call(_0x80a9ee,0x633);
  api.eventClient = uVar15;
  uVar15 = Call(_0x80a9ee,0x9c);
  api.zaap = uVar15;
  uVar15 = Construct(_0x3817cc.Client,iVar6);
  api.discordRpc = uVar15;
  iVar4 = api.discordRpc;
  CallProperty(iVar4.login,iVar4,iVar7);
  cVar1 = LooseEquals("1",process.env.ENABLE_MODREPORTSMANAGER);
  if (cVar1 != '\0') {
    CallProperty(console.log,console,"ModReportsManager Loaded");
    uVar15 = Call(_0x80a9ee,0x256d);
    api.modReportsManager = uVar15;
  }
  api.siDataValid = false;
  api.cfDataValid = false;
  return undefined;
}
/* anonymous_65 [lit 65, 0 args] <- 7318 */
undefined4 anonymous_65(undefined4 receiver)
{
  CreateFunctionContext(scope_anonymous_65);
  iVar2 = api.config;
  uVar3 = CallProperty(iVar2.get,iVar2,"sCurrentLanguage");
  cVar1 = LooseEquals("",uVar3);
  if (cVar1 == '\0') {
    iVar2 = api.utils;
    iVar4 = api.config;
    uVar3 = CallProperty(iVar4.get,iVar4,"sCurrentLanguage");
    uVar3 = CallProperty(iVar2.checkClientLanguage,iVar2,uVar3);
    iVar2 = api.config;
    uVar5 = CallProperty(iVar2.get,iVar2,"sCurrentLanguage");
    cVar1 = LooseEquals(uVar3,uVar5);
    if (cVar1 != '\0') goto LAB_100c18d2;
  }
  iVar2 = CallProperty(_0xbb8866.getLocale,_0xbb8866);
  uVar3 = CallProperty(iVar2.split,iVar2,"-");
  iVar2 = GetProperty(uVar3,0);
  uVar3 = CallProperty(iVar2.toLowerCase,iVar2);
  cVar1 = IsUndetectable(uVar3);
  if ((cVar1 == '\0') && (cVar1 = LooseEquals("",uVar3), cVar1 == '\0')) {
    iVar2 = api.config;
    iVar4 = api.utils;
    uVar3 = CallProperty(iVar4.checkClientLanguage,iVar4,uVar3);
    CallProperty(iVar2.set,iVar2,"sCurrentLanguage",uVar3);
  }
  else {
    iVar2 = api.config;
    CallProperty(iVar2.set,iVar2,"sCurrentLanguage","fr");
  }
LAB_100c18d2:
  iVar2 = api.i18n;
  iVar4 = api.config;
  uVar3 = CallProperty(iVar4.get,iVar4,"sCurrentLanguage");
  CallProperty(iVar2.setLocale,iVar2,uVar3);
  uVar3 = Call(_0x80a9ee,0x14c4);
  api.menu = uVar3;
  return undefined;
}
