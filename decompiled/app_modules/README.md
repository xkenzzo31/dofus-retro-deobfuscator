# Code applicatif de `main.jsc` (Dofus Retro 1.49), décompilé par REA

Pseudo-code produit par REA (Ghidra 12.1.4 + extension `ghidra-v8-87`, chaînes obfuscator.io déchiffrées) sur
`main.jsc` SHA-256 `6183261b…0919`. Ce n'est pas le source d'origine : c'est la sortie du décompilateur Ghidra.

Seules les fonctions **vivantes** de chaque module sont gardées. On part de la fonction du module webpack et on
suit les `CreateClosure` du code décompilé. Le code mort injecté par obfuscator.io et les wrappers de chaînes
sont donc écartés.

| Fichier | Module webpack | Rôle |
|---|---|---|
| `00_entry_main.c` | entrée (`anonymous_9065`) | switches Chromium, chargement PepperFlash, `app.on(...)`, 24 relais `ipcMain` |
| `7318_api_root.c` | 7318 | construit `global.api` (`init` / `initOnReady`), i18n, store de réglages, Discord |
| `9066_api_game_windows_flash.c` | 9066 → `api.game` | fenêtres (jeu, chat, console), `mms.cfg`, FlashPlayerTrust, `.sol`, Discord, options |
| `4288_api_utils.c` | 4288 → `api.utils` | logs `RetroLogs/`, fichiers, dates, langue, échappement ExternalInterface |
| `1587_api_eventClient.c` | 1587 → `api.eventClient` | compteurs d'UI → `EV1` / `EV2;…` (paquets `Ge`) |
| `156_api_zaap_thrift.c` | 156 → `api.zaap` | client Thrift du launcher Zaap |
| `5316_api_menu.c` | 5316 → `api.menu` | menu applicatif (et menu « Dev » en mode `electron .`) |
| `9581_modReportsManager_masked.c` | 9581 → `api.modReportsManager` | rapports de modération (chargé seulement si `ENABLE_MODREPORTSMANAGER=1`) ; longues chaînes opaques masquées |

Le module Shield (`406` → `api.security`) n'est volontairement pas extrait ici.

Preuves REA de la session du 23/10 : `ev_0df7ec7f40f75f707bea9d073823aeaa3c2d4a6c2b7d385200a7a0ed722ba362`
(`batch_decompile` de 21 fonctions de ces modules, identiques à ce corpus) et
`ev_8ecb54dadeac4e5cd20012082a24c22422a1ffd7227566126bf9247bab272c4f` (module d'entrée).
