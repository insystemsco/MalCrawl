// Generic rules

rule gen_attack_5 {
  strings:
    $a = "attack" ascii wide nocase

  condition:
    #a >= 5
}

rule gen_backdoor_5 {
  strings:
    $a = "backdoor" ascii wide nocase

  condition:
    #a >= 5
}

rule gen_bootkit_5 {
  strings:
    $a = "bootkit" ascii wide nocase

  condition:
    #a >= 5
}

rule gen_bot_5 {
  strings:
    $a = "bot" ascii wide nocase

  condition:
    #a >= 5
}

rule gen_botnet_5 {
  strings:
    $a = "botnet" ascii wide nocase

  condition:
    #a >= 5
}

rule gen_ddos_5 {
  strings:
    $a = "ddos" ascii wide nocase

  condition:
    #a >= 5
}

rule gen_exploit_5 {
  strings:
    $a = "exploit" ascii wide nocase

  condition:
    #a >= 5
}

rule gen_infect_5 {
  strings:
    $a = "infect" ascii wide nocase

  condition:
    #a >= 5
}

rule gen_inject_5 {
  strings:
    $a = "inject" ascii wide nocase

  condition:
    #a >= 5
}

rule gen_hack_5 {
  strings:
    $a = "hack" ascii wide nocase

  condition:
    #a >= 5
}

rule gen_keylogger_5 {
  strings:
    $a = "keylogger" ascii wide nocase

  condition:
    #a >= 5
}

rule gen_malware_5 {
  strings:
    $a = "malware" ascii wide nocase

  condition:
    #a >= 5
}      

rule gen_ransom_5 {
  strings:
    $a = "ransom" ascii wide nocase

  condition:
    #a >= 5
}

rule gen_rat_5 {
  strings:
    $a = "rat" ascii wide nocase

  condition:
    #a >= 5
}

rule gen_rootkit_5 {
  strings:
    $a = "rootkit" ascii wide nocase

  condition:
    #a >= 5
}

rule gen_trojan_5 {
  strings:
    $a = "trojan" ascii wide nocase

  condition:
    #a >= 5
}

rule gen_virus_5 {
  strings:
    $a = "virus" ascii wide nocase

  condition:
    #a >= 5
}

rule gen_vuln_5 {
  strings:
    $a = "vuln" ascii wide nocase

  condition:
    #a >= 5
}

rule gen_worm_5 {
  strings:
    $a = "worm" ascii wide nocase

  condition:
    #a >= 5
}

// Registry rules

rule registry_5 {
  strings:
    $a = "registry" ascii wide nocase

  condition:
    all of them
}

rule registry_run {
  strings:
    $a = "\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide nocase

  condition:
    all of them
}

rule registry_regkey_5 {
  strings:
    $a = "regkey" ascii wide nocase

  condition:
    #a >= 5
}

rule registry_HKEY_5 {
  strings:
    $a = "HKEY" ascii wide nocase

  condition:
    #a >= 5
}

rule registry_HKCU_5 {
  strings:
    $a = "HKCU" ascii wide nocase

  condition:
    #a >= 5
}

rule registry_HKLM_5 {
  strings:
    $a = "HKLM" ascii wide nocase

  condition:
    #a >= 5
}

// Bank
rule bank_5 {
  strings:
    $a = /(bank)|(banco)/ ascii wide nocase

  condition:
    #a >= 5
}

// Paypal

rule paypal_5 {
  strings:
    $a = "paypal" ascii wide nocase

  condition:
    #a >= 5
}

// Bitcoin

rule bitcoin_5 {
  strings:
    $a = "bitcoin" ascii wide nocase

  condition:
    #a >= 5
}

rule bitcoin_btc_5 {
  strings:
    $a = "btc" ascii wide nocase

  condition:
    #a >= 5
}      

rule bitcoin_blockchain_5 {
  strings:
    $a = "blockchain" ascii wide nocase

  condition:
    #a >= 5
}

rule bitcoin_blockr_5 {
  strings:
    $a = "blockr" ascii wide nocase

  condition:
    #a >= 5 
}

rule bitcoin_wallet {
  strings:
    $a = /[13][a-km-zA-HJ-NP-Z1-9]{25,34}/ fullword ascii wide nocase

  condition:
    all of them
}

// Ransomware note

rule ransom_delete_5 {
  strings:
    $a = "delete" ascii wide nocase

  condition:
    #a >= 5
}

rule ransom_payment_5 {
  strings:
    $a = "payment" ascii wide nocase

  condition:
    #a >= 5	
}

rule ransom_locker_5 {
  strings:
    $a = "locker" ascii wide nocase

  condition:
    #a >= 5
}

// Network

rule network {
  strings:
    $a = "network" ascii wide nocase

  condition:
    #a >= 5
}

rule network_cnc {
  strings:
    $a = /(c&c)|(c2)/ fullword ascii wide nocase
    $b = "cnc" ascii wide nocase

  condition:
    #a >= 5 or #b >= 5
}

rule network_exfil {
  strings:
    $a = "exfil" ascii wide nocase

  condition:
    #a >= 5
}

rule network_connect {
  strings:
    $a = "connect" ascii wide nocase

  condition:
    #a >= 5
}

rule network_ping {
  strings:
    $a = "ping" ascii wide nocase

  condition:
    #a >= 5
}

rule network_socket {
  strings:
    $a = "socket" ascii wide nocase

  condition:
    #a >= 5
}

rule network_eth0 {
  strings:
    $a = "eth0" ascii wide nocase

  condition:
    #a >= 5
}

// Crypto

rule crypto {
  strings:
    $a = "crypt" ascii wide nocase

  condition:
    #a >= 5
}

rule crypto_aes {
  strings:
    $a = "aes" ascii wide nocase

  condition:
    #a >= 5
}

rule crypto_rsa {
  strings:
    $a = "rsa" ascii wide nocase

  condition:
    #a >= 5
}

// Packing

rule packer_upx {
  strings:
    $a = "upx" ascii wide nocase

  condition:
    #a >= 5
}

rule packer_nsis {
  strings:
    $a = "nsis" ascii wide nocase

  condition:
    #a >= 5
}

// Mutex

rule mutex {
  strings:
    $a = "mutex" ascii wide nocase

  condition:
    #a >= 5
}      

// Other

rule other_loadlibrary {
  strings:
    $a = "loadlibrary" ascii wide nocase

  condition:
    all of them
}
      