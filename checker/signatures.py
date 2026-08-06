# -*- coding: utf-8 -*-
"""
База сигнатур Mine Checker.

Три уровня обнаружения:
  1. NAME  - имя файла/папки/процесса совпадает с известным читом (в т.ч. алиасы).
  2. MARKER- внутри .jar найдены пакеты/строки конкретного клиента (ловит переименование).
  3. HEUR  - в .jar найден набор модулей чита (KillAura, Velocity, Scaffold...),
             название при этом может быть любым - это ловит приватные/новые/ребрендженные читы.
"""

# ---------------------------------------------------------------------------
# Уровни опасности
# ---------------------------------------------------------------------------
SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
SEVERITY_RU = {
    "critical": "КРИТИЧНО",
    "high": "ВЫСОКИЙ",
    "medium": "СРЕДНИЙ",
    "low": "НИЗКИЙ",
    "info": "ИНФО",
}
SEVERITY_COLOR = {
    "critical": "#ff4d5e",
    "high": "#ff8b3d",
    "medium": "#ffd23f",
    "low": "#5ac8fa",
    "info": "#8b93a7",
}

# Категории находок
CAT_CLIENT = "Чит-клиент"
CAT_MOD = "Чит-мод / утилита"
CAT_GHOST = "Ghost-клиент"
CAT_BEDROCK = "Bedrock-чит"
CAT_INJECT = "Инжектор / агент"
CAT_MACRO = "Макросы / автокликер"
CAT_CLEANER = "Зачистка следов"
CAT_TRACE = "След удалённого файла"
CAT_PROC = "Процесс"
CAT_MC = "Minecraft"
CAT_GREY = "Серая зона"
CAT_SYS = "Система"

# ---------------------------------------------------------------------------
# КЛИЕНТЫ. sev - опасность, aliases - как называют файл/папку, markers - строки
# внутри jar (пакеты, классы, ресурсы), которые остаются даже после переименования.
# ---------------------------------------------------------------------------
CLIENTS = {
    # --- Крупные публичные Java-клиенты -----------------------------------
    "Wurst":          {"sev": "critical", "cat": CAT_CLIENT, "aliases": ["wurst", "wurstclient", "wurst client", "wurst7", "wurst-client"], "markers": ["net/wurstclient", "wurstclient.json"]},
    "Impact":         {"sev": "critical", "cat": CAT_CLIENT, "aliases": ["impact client", "impactclient", "impact-", "impactdevelopment"], "markers": ["impactdevelopment", "com/mentalfrostbyte/jello"]},
    "Meteor Client":  {"sev": "critical", "cat": CAT_CLIENT, "aliases": ["meteor client", "meteorclient", "meteor-client", "meteordevelopment"], "markers": ["meteordevelopment/meteorclient"]},
    "Future":         {"sev": "critical", "cat": CAT_CLIENT, "aliases": ["future client", "futureclient", "future vip", "futurevip"], "markers": ["futureclient"]},
    "Sigma":          {"sev": "critical", "cat": CAT_CLIENT, "aliases": ["sigma client", "sigmaclient", "sigma5", "sigma 5", "sigma4"], "markers": ["sigmaclient"]},
    "Aristois":       {"sev": "critical", "cat": CAT_CLIENT, "aliases": ["aristois"], "markers": ["aristois"]},
    "LiquidBounce":   {"sev": "critical", "cat": CAT_CLIENT, "aliases": ["liquidbounce", "liquid bounce", "ccbluex", "liquidsense"], "markers": ["net/ccbluex/liquidbounce", "ccbluex"]},
    "RusherHack":     {"sev": "critical", "cat": CAT_CLIENT, "aliases": ["rusherhack", "rusher hack", "rusher"], "markers": ["org/rusherhack"]},
    "Konas":          {"sev": "critical", "cat": CAT_CLIENT, "aliases": ["konas"], "markers": ["me/konas"]},
    "Inertia":        {"sev": "critical", "cat": CAT_CLIENT, "aliases": ["inertia client", "inertiaclient"], "markers": []},
    "KAMI Blue":      {"sev": "critical", "cat": CAT_CLIENT, "aliases": ["kami blue", "kamiblue", "kami-blue"], "markers": ["org/kamiblue", "me/zeroeightsix/kami"]},
    "SalHack":        {"sev": "critical", "cat": CAT_CLIENT, "aliases": ["salhack", "sal hack"], "markers": ["salhack"]},
    "Phobos":         {"sev": "critical", "cat": CAT_CLIENT, "aliases": ["phobos client", "phobosclient"], "markers": []},
    "Seppuku":        {"sev": "critical", "cat": CAT_CLIENT, "aliases": ["seppuku"], "markers": ["me/rigamortis/seppuku"]},
    "GameSense":      {"sev": "critical", "cat": CAT_CLIENT, "aliases": ["gamesense", "game sense"], "markers": ["com/gamesense/client"]},
    "ForgeHax":       {"sev": "critical", "cat": CAT_CLIENT, "aliases": ["forgehax", "forge hax"], "markers": ["com/matt/forgehax"]},
    "BleachHack":     {"sev": "critical", "cat": CAT_CLIENT, "aliases": ["bleachhack", "bleach hack"], "markers": ["org/bleachhack"]},
    "Trouser Streak": {"sev": "critical", "cat": CAT_CLIENT, "aliases": ["trouserstreak", "trouser streak"], "markers": ["trouserstreak"]},
    "Wolfram":        {"sev": "critical", "cat": CAT_CLIENT, "aliases": ["wolfram client", "wolframclient"], "markers": ["net/wolfram"]},
    "Nodus":          {"sev": "critical", "cat": CAT_CLIENT, "aliases": ["nodus"], "markers": []},
    "Huzuni":         {"sev": "critical", "cat": CAT_CLIENT, "aliases": ["huzuni"], "markers": ["net/halalaboos/huzuni"]},
    "Jigsaw":         {"sev": "critical", "cat": CAT_CLIENT, "aliases": ["jigsaw client", "jigsawclient"], "markers": []},
    "SkillClient":    {"sev": "critical", "cat": CAT_CLIENT, "aliases": ["skillclient", "skill client"], "markers": ["skillclient"]},
    "WeepCraft":      {"sev": "critical", "cat": CAT_CLIENT, "aliases": ["weepcraft", "weep craft"], "markers": ["weepcraft"]},
    "Zamorozka":      {"sev": "critical", "cat": CAT_CLIENT, "aliases": ["zamorozka", "заморозка"], "markers": ["zamorozka"]},
    "Doomsday":       {"sev": "critical", "cat": CAT_CLIENT, "aliases": ["doomsday client", "doomsdayclient"], "markers": []},
    "Aoba":           {"sev": "critical", "cat": CAT_CLIENT, "aliases": ["aoba client", "aobaclient"], "markers": ["net/aoba"]},
    "Tarasande":      {"sev": "critical", "cat": CAT_CLIENT, "aliases": ["tarasande"], "markers": ["net/tarasande"]},
    "CrossSine":      {"sev": "critical", "cat": CAT_CLIENT, "aliases": ["crosssine", "cross sine"], "markers": ["crosssine"]},
    "Sakura":         {"sev": "critical", "cat": CAT_CLIENT, "aliases": ["sakura client", "sakuraclient"], "markers": []},
    "Radium":         {"sev": "critical", "cat": CAT_CLIENT, "aliases": ["radium client", "radiumclient"], "markers": []},
    "Cyde":           {"sev": "critical", "cat": CAT_CLIENT, "aliases": ["cyde client", "cydeclient", "cyde.xyz"], "markers": []},
    "Xulu":           {"sev": "critical", "cat": CAT_CLIENT, "aliases": ["xulu client", "xuluclient"], "markers": []},
    "Ares":           {"sev": "critical", "cat": CAT_CLIENT, "aliases": ["ares client", "aresclient"], "markers": []},
    "Ratpoison":      {"sev": "critical", "cat": CAT_CLIENT, "aliases": ["ratpoison", "rat poison"], "markers": []},
    "Marlin":         {"sev": "critical", "cat": CAT_CLIENT, "aliases": ["marlin client", "marlinclient"], "markers": []},
    "Zeroday":        {"sev": "critical", "cat": CAT_CLIENT, "aliases": ["zeroday", "zero day client"], "markers": []},
    "Entropy":        {"sev": "critical", "cat": CAT_CLIENT, "aliases": ["entropy client", "entropyclient"], "markers": []},
    "Slinky":         {"sev": "critical", "cat": CAT_CLIENT, "aliases": ["slinky client", "slinkyclient"], "markers": []},
    "Augustus":       {"sev": "critical", "cat": CAT_CLIENT, "aliases": ["augustus client", "augustusclient", "jello client"], "markers": ["com/mentalfrostbyte/jello"]},
    "Exhibition":     {"sev": "critical", "cat": CAT_CLIENT, "aliases": ["exhibition client", "exhibitionclient"], "markers": []},

    # --- 1.8 PvP / легаси ---------------------------------------------------
    "Flux":           {"sev": "critical", "cat": CAT_CLIENT, "aliases": ["flux client", "fluxclient", "flux b", "fluxb"], "markers": []},
    "Astolfo":        {"sev": "critical", "cat": CAT_CLIENT, "aliases": ["astolfo"], "markers": ["astolfo"]},
    "Novoline":       {"sev": "critical", "cat": CAT_CLIENT, "aliases": ["novoline", "novo line"], "markers": ["cc/novoline"]},
    "Moon Client":    {"sev": "critical", "cat": CAT_CLIENT, "aliases": ["moon client", "moonclient"], "markers": []},
    "Rise":           {"sev": "critical", "cat": CAT_CLIENT, "aliases": ["rise client", "riseclient", "rise 6", "rise6"], "markers": []},
    "Raven":          {"sev": "critical", "cat": CAT_CLIENT, "aliases": ["raven client", "ravenclient", "raven b++", "ravenb"], "markers": []},
    "Reflex":         {"sev": "critical", "cat": CAT_CLIENT, "aliases": ["reflex client", "reflexclient"], "markers": []},
    "Ripple":         {"sev": "critical", "cat": CAT_CLIENT, "aliases": ["ripple client", "rippleclient"], "markers": []},
    "Tenacity":       {"sev": "critical", "cat": CAT_CLIENT, "aliases": ["tenacity client", "tenacityclient"], "markers": []},
    "Zenith":         {"sev": "critical", "cat": CAT_CLIENT, "aliases": ["zenith client", "zenithclient"], "markers": []},
    "Sensa":          {"sev": "critical", "cat": CAT_CLIENT, "aliases": ["sensa client", "sensaclient"], "markers": []},
    "Kryptonite":     {"sev": "critical", "cat": CAT_CLIENT, "aliases": ["kryptonite client"], "markers": []},
    "Photon":         {"sev": "critical", "cat": CAT_CLIENT, "aliases": ["photon client", "photonclient"], "markers": []},
    "Zeus":           {"sev": "critical", "cat": CAT_CLIENT, "aliases": ["zeus client", "zeusclient"], "markers": []},
    "Skid":           {"sev": "high",     "cat": CAT_CLIENT, "aliases": ["skid client", "skidclient"], "markers": []},

    # --- Ghost / приватные (обход скринчека) --------------------------------
    "Vape":           {"sev": "critical", "cat": CAT_GHOST, "aliases": ["vape", "vapev4", "vape v4", "vapelite", "vape lite", "vape client", "vapev3"], "markers": ["me/vape"]},
    "Prestige":       {"sev": "critical", "cat": CAT_GHOST, "aliases": ["prestige client", "prestigeclient"], "markers": []},
    "Nightmare":      {"sev": "critical", "cat": CAT_GHOST, "aliases": ["nightmare client", "nightmareclient"], "markers": []},
    "Deadcode":       {"sev": "critical", "cat": CAT_GHOST, "aliases": ["deadcode", "dead code client"], "markers": []},
    "Fatality":       {"sev": "critical", "cat": CAT_GHOST, "aliases": ["fatality client", "fatalityclient"], "markers": []},
    "Akrien":         {"sev": "critical", "cat": CAT_GHOST, "aliases": ["akrien"], "markers": []},
    "Myau":           {"sev": "critical", "cat": CAT_GHOST, "aliases": ["myau", "myau client"], "markers": ["myauclient"]},
    "Cold":           {"sev": "critical", "cat": CAT_GHOST, "aliases": ["cold client", "coldclient", "bypassing.gg"], "markers": []},
    "Wexside":        {"sev": "critical", "cat": CAT_GHOST, "aliases": ["wexside"], "markers": []},
    "Celestial":      {"sev": "critical", "cat": CAT_GHOST, "aliases": ["celestial client", "celestialclient"], "markers": []},
    "Solstice":       {"sev": "critical", "cat": CAT_GHOST, "aliases": ["solstice client", "solsticeclient"], "markers": []},
    "Fractal":        {"sev": "critical", "cat": CAT_GHOST, "aliases": ["fractal client", "fractalclient"], "markers": []},
    "NightX":         {"sev": "critical", "cat": CAT_GHOST, "aliases": ["nightx"], "markers": []},
    "Acrimony":       {"sev": "critical", "cat": CAT_GHOST, "aliases": ["acrimony"], "markers": []},

    # --- СНГ / анархии ------------------------------------------------------
    "Nursultan":      {"sev": "critical", "cat": CAT_CLIENT, "aliases": ["nursultan", "нурсултан"], "markers": ["me/nursultan", "nursultan"]},
    "Expensive":      {"sev": "critical", "cat": CAT_CLIENT, "aliases": ["expensive", "экспенсив"], "markers": ["im/expensive"]},
    "Excellent":      {"sev": "critical", "cat": CAT_CLIENT, "aliases": ["excellent client", "excellent recode", "экселлент"], "markers": []},
    "Rockstar":       {"sev": "critical", "cat": CAT_CLIENT, "aliases": ["rockstar client", "rockstarclient", "rockstar.pub"], "markers": []},
    "Sunrise":        {"sev": "critical", "cat": CAT_CLIENT, "aliases": ["sunrise client", "sunriseclient"], "markers": []},
    "Neverlose":      {"sev": "critical", "cat": CAT_CLIENT, "aliases": ["neverlose"], "markers": []},
    "Neverix":        {"sev": "critical", "cat": CAT_CLIENT, "aliases": ["neverix"], "markers": []},
    "Season":         {"sev": "critical", "cat": CAT_CLIENT, "aliases": ["season client", "season.new", "seasonclient"], "markers": []},
    "HashClient":     {"sev": "critical", "cat": CAT_CLIENT, "aliases": ["hashclient", "hash client"], "markers": []},
    "EvaWare":        {"sev": "critical", "cat": CAT_CLIENT, "aliases": ["evaware", "eva ware"], "markers": []},
    "Desteni":        {"sev": "critical", "cat": CAT_CLIENT, "aliases": ["desteni"], "markers": []},
    "Arbuz":          {"sev": "critical", "cat": CAT_CLIENT, "aliases": ["arbuz client", "arbuzclient", "арбуз"], "markers": []},
    "Blade":          {"sev": "critical", "cat": CAT_CLIENT, "aliases": ["blade client", "bladeclient"], "markers": []},
    "Awesome":        {"sev": "critical", "cat": CAT_CLIENT, "aliases": ["awesome client", "awesomeclient"], "markers": []},
    "Rich":           {"sev": "critical", "cat": CAT_CLIENT, "aliases": ["rich client", "richclient"], "markers": []},
    "Ryzen Client":   {"sev": "critical", "cat": CAT_CLIENT, "aliases": ["ryzen client", "ryzenclient"], "markers": []},
    "ProtonHack":     {"sev": "critical", "cat": CAT_CLIENT, "aliases": ["protonhack", "proton hack"], "markers": []},

    # --- Bedrock ------------------------------------------------------------
    "Horion":         {"sev": "critical", "cat": CAT_BEDROCK, "aliases": ["horion"], "markers": ["horionclient"]},
    "Toolbox":        {"sev": "high",     "cat": CAT_BEDROCK, "aliases": ["toolbox for minecraft"], "markers": []},
    "Packet (BE)":    {"sev": "critical", "cat": CAT_BEDROCK, "aliases": ["packet client"], "markers": []},
    "Nitro (BE)":     {"sev": "critical", "cat": CAT_BEDROCK, "aliases": ["nitro client", "nitroclient"], "markers": []},
    "Borion":         {"sev": "critical", "cat": CAT_BEDROCK, "aliases": ["borion"], "markers": []},
    "Flarial":        {"sev": "critical", "cat": CAT_BEDROCK, "aliases": ["flarial"], "markers": ["flarialclient"]},
    "Prax":           {"sev": "critical", "cat": CAT_BEDROCK, "aliases": ["prax client", "praxclient"], "markers": []},
    "Zephyr (BE)":    {"sev": "critical", "cat": CAT_BEDROCK, "aliases": ["zephyr client"], "markers": []},
    "Onix":           {"sev": "critical", "cat": CAT_BEDROCK, "aliases": ["onix client", "onixclient"], "markers": []},
    "Ambrosial":      {"sev": "critical", "cat": CAT_BEDROCK, "aliases": ["ambrosial"], "markers": []},
}

# ---------------------------------------------------------------------------
# Читерские моды/утилиты (отдельные .jar, не полноценные клиенты)
# ---------------------------------------------------------------------------
CHEAT_MODS = {
    "X-Ray мод":        {"sev": "critical", "cat": CAT_MOD, "aliases": ["xray", "x-ray", "x_ray", "xray mod", "xrayultimate", "xray ultimate", "seethrough", "see through", "oremod", "ore finder"], "markers": []},
    "Killaura мод":     {"sev": "critical", "cat": CAT_MOD, "aliases": ["killaura", "kill aura", "aurahack", "triggerbot", "trigger bot", "aimbot", "aim assist", "aimassist"], "markers": []},
    "Reach мод":        {"sev": "critical", "cat": CAT_MOD, "aliases": ["reachmod", "reach hack", "hitbox expander", "reach cheat"], "markers": []},
    "Velocity/AntiKB":  {"sev": "critical", "cat": CAT_MOD, "aliases": ["antiknockback", "anti knockback", "velocitymod", "no knockback"], "markers": []},
    "Автокликер-мод":   {"sev": "critical", "cat": CAT_MOD, "aliases": ["autoclicker", "auto clicker", "autoclick", "clicker mod", "butterfly click", "drag click", "jitter click"], "markers": []},
    "Bhop / Speed":     {"sev": "critical", "cat": CAT_MOD, "aliases": ["bhopmod", "bunnyhop", "speedhack", "speed hack", "strafe hack"], "markers": []},
    "Scaffold":         {"sev": "critical", "cat": CAT_MOD, "aliases": ["scaffold", "towermod", "bridge assist"], "markers": []},
    "Nuker":            {"sev": "critical", "cat": CAT_MOD, "aliases": ["nuker", "fastbreak", "fast break", "instabreak"], "markers": []},
    "ESP / Tracers":    {"sev": "critical", "cat": CAT_MOD, "aliases": ["espmod", "esp mod", "chestesp", "playeresp", "tracers mod", "wallhack", "wall hack"], "markers": []},
    "AutoTotem":        {"sev": "critical", "cat": CAT_MOD, "aliases": ["autototem", "auto totem", "totempop"], "markers": []},
    "AutoCrystal":      {"sev": "critical", "cat": CAT_MOD, "aliases": ["autocrystal", "auto crystal", "crystalaura", "crystal aura"], "markers": []},
    "Fly / NoFall":     {"sev": "critical", "cat": CAT_MOD, "aliases": ["flymod", "fly hack", "nofall", "no fall", "elytrafly", "elytra bot"], "markers": []},
    "AutoFish":         {"sev": "high",     "cat": CAT_MOD, "aliases": ["autofish", "auto fish", "fishing bot", "afk fish"], "markers": []},
    "ChestStealer":     {"sev": "critical", "cat": CAT_MOD, "aliases": ["cheststealer", "chest stealer", "inventory cleaner hack"], "markers": []},
    "Freecam":          {"sev": "high",     "cat": CAT_MOD, "aliases": ["freecam", "free cam", "freelook hack"], "markers": []},
    "Fullbright":       {"sev": "medium",   "cat": CAT_MOD, "aliases": ["fullbright", "full bright", "gamma mod", "brightness hack"], "markers": []},
    "AntiAFK / бот":    {"sev": "high",     "cat": CAT_MOD, "aliases": ["antiafk", "anti afk", "afkbot", "afk bot", "macro bot"], "markers": []},
    "Baritone":         {"sev": "high",     "cat": CAT_MOD, "aliases": ["baritone"], "markers": []},
    "Bhop скрипт":      {"sev": "high",     "cat": CAT_MOD, "aliases": ["bhop.lua", "bhop script"], "markers": []},
    "Ghost инжект-мод": {"sev": "critical", "cat": CAT_MOD, "aliases": ["ghostclient", "ghost client", "ghost mod", "undetected client"], "markers": []},
}

# ---------------------------------------------------------------------------
# Инжекторы, отладчики, java-агенты
# ---------------------------------------------------------------------------
INJECTORS = {
    "Extreme Injector":   {"sev": "critical", "cat": CAT_INJECT, "aliases": ["extreme injector", "extremeinjector"]},
    "Xenos Injector":     {"sev": "critical", "cat": CAT_INJECT, "aliases": ["xenos", "xenos64", "xenosinjector"]},
    "GH Injector":        {"sev": "critical", "cat": CAT_INJECT, "aliases": ["gh injector", "ghinjector"]},
    "Process Hacker":     {"sev": "high",     "cat": CAT_INJECT, "aliases": ["process hacker", "processhacker", "system informer", "systeminformer"]},
    "Cheat Engine":       {"sev": "critical", "cat": CAT_INJECT, "aliases": ["cheat engine", "cheatengine", "cheatengine-x86_64"]},
    "x64dbg / OllyDbg":   {"sev": "high",     "cat": CAT_INJECT, "aliases": ["x64dbg", "x32dbg", "ollydbg"]},
    "Java-агент":         {"sev": "critical", "cat": CAT_INJECT, "aliases": ["javaagent", "java agent", "agent.jar", "injector.jar", "inject.jar", "jinjector", "jnativehook injector"]},
    "Универс. инжектор":  {"sev": "critical", "cat": CAT_INJECT, "aliases": ["injector.exe", "injector64", "dll injector", "dllinjector", "winject", "loader.exe (чит)"]},
    "JavaAgent loader":   {"sev": "critical", "cat": CAT_INJECT, "aliases": ["attach.jar", "vminject", "hotswap agent"]},
}

# ---------------------------------------------------------------------------
# Макросы / автокликеры / ПО мышей
# ---------------------------------------------------------------------------
MACRO_TOOLS = {
    "OP Auto Clicker":    {"sev": "critical", "cat": CAT_MACRO, "aliases": ["op auto clicker", "opautoclicker"]},
    "GS Auto Clicker":    {"sev": "critical", "cat": CAT_MACRO, "aliases": ["gs auto clicker", "gsautoclicker"]},
    "Speed Autoclicker":  {"sev": "critical", "cat": CAT_MACRO, "aliases": ["speedautoclicker", "speed autoclicker", "orphamielautoclicker"]},
    "Free Mouse Clicker": {"sev": "critical", "cat": CAT_MACRO, "aliases": ["free mouse clicker", "freeautoclicker", "murgee"]},
    "TinyTask":           {"sev": "high",     "cat": CAT_MACRO, "aliases": ["tinytask"]},
    "AutoHotkey":         {"sev": "high",     "cat": CAT_MACRO, "aliases": ["autohotkey", "ahk.exe", "autohotkeyu64"]},
    "AutoIt":             {"sev": "high",     "cat": CAT_MACRO, "aliases": ["autoit3", "autoit"]},
    "Mouse Recorder":     {"sev": "high",     "cat": CAT_MACRO, "aliases": ["mouse recorder", "mouserecorder", "macro recorder", "macrorecorder", "pulover"]},
    "Bloody / A4Tech":    {"sev": "high",     "cat": CAT_MACRO, "aliases": ["bloody6", "bloody7", "a4tech", "oscar editor", "oscar mouse editor", "x7"]},
    "Razer Synapse":      {"sev": "medium",   "cat": CAT_MACRO, "aliases": ["razer synapse", "razersynapse"]},
    "Logitech G HUB/LGS": {"sev": "medium",   "cat": CAT_MACRO, "aliases": ["lghub", "g hub", "logitech gaming software", "lcore"]},
    "Corsair iCUE":       {"sev": "medium",   "cat": CAT_MACRO, "aliases": ["icue", "corsair icue"]},
    "SteelSeries GG":     {"sev": "medium",   "cat": CAT_MACRO, "aliases": ["steelseries gg", "steelseries engine"]},
    "Karabiner (macOS)":  {"sev": "medium",   "cat": CAT_MACRO, "aliases": ["karabiner", "karabiner-elements"]},
    "Keyboard Maestro":   {"sev": "medium",   "cat": CAT_MACRO, "aliases": ["keyboard maestro"]},
    "BetterTouchTool":    {"sev": "medium",   "cat": CAT_MACRO, "aliases": ["bettertouchtool"]},
    "Hammerspoon":        {"sev": "medium",   "cat": CAT_MACRO, "aliases": ["hammerspoon"]},
    "Auto Clicker macOS": {"sev": "critical", "cat": CAT_MACRO, "aliases": ["autoclicker.app", "auto clicker.app", "clickr", "murgee auto clicker"]},
}

# ---------------------------------------------------------------------------
# Зачистка следов / антифорензика (сам факт наличия - повод для вопросов)
# ---------------------------------------------------------------------------
CLEANERS = {
    "CCleaner":          {"sev": "high",     "cat": CAT_CLEANER, "aliases": ["ccleaner", "ccleaner64"]},
    "BleachBit":         {"sev": "high",     "cat": CAT_CLEANER, "aliases": ["bleachbit"]},
    "Privazer":          {"sev": "high",     "cat": CAT_CLEANER, "aliases": ["privazer"]},
    "Wise Disk Cleaner": {"sev": "high",     "cat": CAT_CLEANER, "aliases": ["wise disk cleaner", "wise care"]},
    "Eraser / Shredder": {"sev": "critical", "cat": CAT_CLEANER, "aliases": ["eraser.exe", "file shredder", "fileshredder", "sdelete", "wipefile", "hardwipe"]},
    "Timestomp-утилиты": {"sev": "critical", "cat": CAT_CLEANER, "aliases": ["setmace", "bulkfilechanger", "newfiletime", "attribute changer", "timestomp"]},
    "Recuva / recovery": {"sev": "medium",   "cat": CAT_CLEANER, "aliases": ["recuva", "disk drill", "easeus data recovery"]},
    "Prefetch cleaner":  {"sev": "critical", "cat": CAT_CLEANER, "aliases": ["prefetch cleaner", "usn cleaner", "journal cleaner", "ssclean", "ss cleaner", "antiss", "anti ss", "антисс"]},
    "Onyx (macOS)":      {"sev": "medium",   "cat": CAT_CLEANER, "aliases": ["onyx.app", "cleanmymac", "appcleaner"]},
}

# ---------------------------------------------------------------------------
# Виртуализация и удалённый доступ (способ спрятать чит от проверки)
# ---------------------------------------------------------------------------
EVASION = {
    "Виртуальная машина":  {"sev": "high",   "cat": CAT_SYS, "aliases": ["vmware", "virtualbox", "vboxmanage", "parallels desktop", "qemu", "hyper-v manager", "utm.app", "sandboxie"]},
    "Удалённый доступ":    {"sev": "high",   "cat": CAT_SYS, "aliases": ["anydesk", "teamviewer", "rustdesk", "parsec", "ammyy", "radmin", "supremo", "getscreen", "aeroadmin"]},
    "Виртуальные диски":   {"sev": "medium", "cat": CAT_SYS, "aliases": ["veracrypt", "truecrypt", "daemon tools"]},
}

# ---------------------------------------------------------------------------
# Серая зона: моды, которые на части серверов запрещены
# ---------------------------------------------------------------------------
GREY_MODS = {
    "Litematica":   {"sev": "medium", "cat": CAT_GREY, "aliases": ["litematica"], "markers": ["fi/dy/masa/litematica"]},
    "Tweakeroo":    {"sev": "medium", "cat": CAT_GREY, "aliases": ["tweakeroo"], "markers": ["fi/dy/masa/tweakeroo"]},
    "Schematica":   {"sev": "medium", "cat": CAT_GREY, "aliases": ["schematica", "printer mod"], "markers": ["com/github/lunatrius/schematica"]},
    "MiniHUD":      {"sev": "low",    "cat": CAT_GREY, "aliases": ["minihud"], "markers": ["fi/dy/masa/minihud"]},
    "Xaero's Map":  {"sev": "low",    "cat": CAT_GREY, "aliases": ["xaeros", "xaerominimap", "xaeroworldmap"], "markers": ["xaero/map", "xaero/minimap"]},
    "JourneyMap":   {"sev": "low",    "cat": CAT_GREY, "aliases": ["journeymap"], "markers": ["journeymap"]},
    "VoxelMap":     {"sev": "low",    "cat": CAT_GREY, "aliases": ["voxelmap"], "markers": ["voxelmap"]},
    "ReplayMod":    {"sev": "low",    "cat": CAT_GREY, "aliases": ["replaymod", "replay mod"], "markers": ["replaymod"]},
    "Inventory Tweaks": {"sev": "low", "cat": CAT_GREY, "aliases": ["inventorytweaks", "inventory tweaks"], "markers": ["invtweaks"]},
}

# ---------------------------------------------------------------------------
# Белый список - легитимные моды/лаунчеры, чтобы не поднимать ложную тревогу
# ---------------------------------------------------------------------------
WHITELIST_JAR_PREFIXES = [
    "fabric-api", "fabric-loader", "sodium", "lithium", "phosphor", "starlight", "iris",
    "indium", "modmenu", "cloth-config", "architectury", "forge-", "neoforge", "optifine",
    "jei-", "roughlyenoughitems", "emi-", "rei-", "appleskin", "ferritecore", "lazydfu",
    "krypton", "entityculling", "immediatelyfast", "bobby", "continuity", "mousetweaks",
    "betterf3", "3dskinlayers", "cit-resewn", "authme", "essential", "worldedit", "carpet",
    "malilib", "connectivity", "memoryleakfix", "notenoughcrashes", "smoothboot", "dynamicfps",
]

LAUNCHERS = [
    "tlauncher", "lunar client", "lunarclient", "badlion", "feather client", "featherclient",
    "salwyrr", "prismlauncher", "polymc", "multimc", "atlauncher", "gdlauncher", "curseforge",
    "modrinth app", "technic", "cracked launcher", "sklauncher", "legacy launcher", "tlmods",
]

# ---------------------------------------------------------------------------
# Эвристика: названия модулей чита. Если в одном .jar найдено >= HEUR_THRESHOLD
# разных модулей - это чит-клиент, как бы он ни назывался.
# ---------------------------------------------------------------------------
HEUR_MODULES = [
    "killaura", "aimbot", "triggerbot", "autoclicker", "velocity", "antiknockback", "nofall",
    "scaffold", "tower", "nuker", "fastbreak", "chestesp", "playeresp", "mobesp", "xray",
    "fullbright", "bunnyhop", "bhop", "speedmine", "criticals", "autototem", "autocrystal",
    "crystalaura", "autoarmor", "autoeat", "cheststealer", "inventorymove", "noslowdown",
    "noslow", "freecam", "tracers", "nametags", "reachdisplay", "hitboxes", "blink",
    "packetfly", "elytrafly", "jesus", "spider", "step", "safewalk", "autowalk", "autofish",
    "autofarm", "antibot", "antiaim", "aimassist", "backtrack", "hitselect", "clickgui",
    "hudmodule", "modulemanager", "settingmanager", "notificationmanager", "rotationutils",
    "raytraceutil", "packetevent", "eventmanager", "commandmanager", "friendmanager",
    "targetstrafe", "autoclickergui", "autopot", "autosoup", "autogapple", "surround",
    "burrow", "holefill", "autoanvil", "autoexp", "autotrap", "hotbarrefill", "silentaim",
]
HEUR_THRESHOLD = 5           # столько уникальных модулей = чит
HEUR_THRESHOLD_STRONG = 10   # столько = уверенный чит-клиент

# Строки в манифесте jar, указывающие на java-агент (ghost-инъекция)
AGENT_MANIFEST_KEYS = [
    "premain-class", "agent-class", "can-retransform-classes", "can-redefine-classes",
    "launcher-agent-class",
]

# Опасные JVM-аргументы в профилях лаунчера
BAD_JVM_ARGS = [
    "-javaagent:", "-agentpath:", "-agentlib:", "-xbootclasspath", "-noverify",
    "-dfml.coremods.load", "-dloader.", "--add-opens java.base/java.lang=all-unnamed",
]

# Маркеры читов для поиска в логах Minecraft.
# ВАЖНО: только специфичные строки, которые пишут в лог именно чит-клиенты.
# Раньше здесь были общие слова (impact, injected, transformer, future, cheat,
# hack) — они ловили обычные моды: "mediumStressImpact" (Create), "recipes will
# be injected", "coremod transformer" и т.п. Теперь берём имена, которые не
# встречаются в логах легитимных модов.
LOG_KEYWORDS = [
    "wurst", "wurstclient", "meteor-client", "meteordevelopment", "liquidbounce",
    "ccbluex", "aristois", "rusherhack", "kamiblue", "seppuku", "gamesense",
    "forgehax", "bleachhack", "nursultan", "expensive client", "rockstar client",
    "celestial client", "prestige client", "nightmare client", "vapeclient",
    "vape-client", "sigma client", "sigmaclient", "future client", "futureclient",
    "impact client", "impactclient", "baritone", "killaura", "aimbot", "autoclicker",
    "x-ray", "xray ", "no-slowdown", "scaffoldwalk",
]

# Слова, которые часто встречаются в логах ОБЫЧНЫХ модов и не должны учитываться
# как признак чита, даже если оказались рядом с маркером.
LOG_BENIGN_HINTS = [
    "stressimpact", "will be injected", "coremod", "transformer", "mixin",
    "completablefuture", "futuretask", "in the future", "optifine",
]

# Резалки: расширения, которые обычно не бывают jar-ом (для поиска маскировки)
ARCHIVE_EXTS = {".jar", ".zip", ".apk", ".war", ".ear", ".mrpack", ".litemod", ".jmod"}

# Пути, которые никогда не сканируем (экономия времени + приватность)
SKIP_DIR_NAMES = {
    # системное
    "windows.old", "winsxs", "system32", "syswow64", "driverstore", "servicing",
    "assembly", "installer", "$windows.~ws", "$windows.~bt",
    # приватное - не читаем принципиально
    "photos library.photoslibrary", "mail", "messages", "keychains", "cookies",
    "safari", "signal", "whatsapp", "telegram desktop", "1password", "bitwarden", "keepass",
    # мусор разработчика: сотни тысяч файлов, читов там не бывает
    "node_modules", ".git", ".svn", "__pycache__", "site-packages", "venv", ".venv",
    ".gradle", ".m2", ".cargo", ".rustup", ".npm", ".pnpm-store", ".yarn", ".nvm",
    ".cache", "cache", "caches", "cacheddata", "code cache", "gpucache",
    ".next", ".nuxt", ".parcel-cache", ".terraform", "pods", "carthage", "deriveddata",
    ".idea", ".vscode", ".expo", ".docker", ".kube", ".conda", ".pyenv", ".gem",
    "service worker", "indexeddb", "local storage", "blob_storage",
}


def all_signature_groups():
    """Все группы сигнатур одним списком для сканера имён."""
    return [CLIENTS, CHEAT_MODS, INJECTORS, MACRO_TOOLS, CLEANERS, EVASION, GREY_MODS]


def marker_index():
    """{marker_lower: (имя, severity, категория)} для поиска внутри jar."""
    idx = {}
    for group in (CLIENTS, CHEAT_MODS, GREY_MODS):
        for name, data in group.items():
            for m in data.get("markers", []):
                idx[m.lower()] = (name, data["sev"], data["cat"])
    return idx


def total_signatures():
    n = 0
    for group in all_signature_groups():
        for data in group.values():
            n += len(data.get("aliases", [])) + len(data.get("markers", []))
    return n + len(HEUR_MODULES) + len(LAUNCHERS)
