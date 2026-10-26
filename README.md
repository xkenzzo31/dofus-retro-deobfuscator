# Dofus Retro — désobfuscation du client

Résultat de la désobfuscation du process `main.jsc` (bytecode V8 8.7) du client Dofus Retro, obtenu avec Ghidra et le plugin fourni ici.

- **`ghidra-plugin/`** — chargeur et analyseur V8 8.7 pour Ghidra : définition de langage SLEIGH, loader du bytecode, décodeur de chaînes et scripts d'analyse. C'est lui qui décode le bytecode et résout les chaînes obfusquées (obfuscator.io).
- **`decompiled/`** — la sortie : pseudo-code des modules applicatifs (`app_modules/`) et table des chaînes déchiffrées (`strings.txt`).

Travail de rétro-ingénierie, à des fins de recherche et d'apprentissage. Licence : voir [`LICENSE`](LICENSE).
