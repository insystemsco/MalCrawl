// A collection of generic YARA rules
// These are meant to be used as heuristics to determine the functionality of a source code file

// ---- Generic rules ---- //

rule gen_attack_1 {
  strings:
    $a = "attack" ascii wide nocase

  condition:
    $a
}

rule gen_attack_3 {
  strings:
    $a = "attack" ascii wide nocase

  condition:
    gen_attack_1 and #a >= 3
}

rule gen_attack_5 {
  strings:
    $a = "attack" ascii wide nocase

  condition:
    gen_attack_3 and #a >= 5
}

rule gen_backdoor_1 {
  strings:
    $a = "backdoor" ascii wide nocase

  condition:
    $a
}

rule gen_backdoor_3 {
  strings:
    $a = "backdoor" ascii wide nocase

  condition:
    gen_backdoor_1 and #a >= 3
}

rule gen_backdoor_5 {
  strings:
    $a = "backdoor" ascii wide nocase

  condition:
    gen_backdoor_3 and #a >= 5
}

rule gen_bootkit_1 {
  strings:
    $a = "bootkit" ascii wide nocase

  condition:
    $a
}

rule gen_bootkit_3 {
  strings:
    $a = "bootkit" ascii wide nocase

  condition:
    gen_bootkit_1 and #a >= 3
}

rule gen_bootkit_5 {
  strings:
    $a = "bootkit" ascii wide nocase

  condition:
    gen_bootkit_3 and #a >= 5
}

rule gen_bot_1 {
  strings:
    $a = "bot" ascii wide nocase

  condition:
    $a
}

rule gen_bot_3 {
  strings:
    $a = "bot" ascii wide nocase

  condition:
    gen_bot_1 and #a >= 3
}

rule gen_bot_5 {
  strings:
    $a = "bot" ascii wide nocase

  condition:
    gen_bot_3 and #a >= 5
}

rule gen_botnet_1 {
  strings:
    $a = "botnet" ascii wide nocase

  condition:
    $a
}

rule gen_botnet_3 {
  strings:
    $a = "botnet" ascii wide nocase

  condition:
    gen_botnet_1 and #a >= 3
}

rule gen_botnet_5 {
  strings:
    $a = "botnet" ascii wide nocase

  condition:
    gen_botnet_3 and #a >= 5
}

rule gen_ddos_1 {
  strings:
    $a = "ddos" ascii wide nocase

  condition:
    $a
}

rule gen_ddos_3 {
  strings:
    $a = "ddos" ascii wide nocase

  condition:
    gen_ddos_1 and #a >= 3
}
      
rule gen_ddos_5 {
  strings:
    $a = "ddos" ascii wide nocase

  condition:
    gen_ddos_3 and #a >= 5
}

rule gen_exploit_1
{
  strings:
    $a = "exploit" ascii wide nocase

  condition:
    $a
}

rule gen_exploit_3 {
  strings:
   $a = "exploit" ascii wide nocase

  condition:
    gen_exploit_1 and #a >= 3
}
   
rule gen_exploit_5 {
  strings:
    $a = "exploit" ascii wide nocase

  condition:
    gen_exploit_3 and #a >= 5
}

rule gen_infect_1 {
  strings:
    $a = "infect" ascii wide nocase

  condition:
    $a
}

rule gen_infect_3 {
  strings:
    $a = "infect" ascii wide nocase

  condition:
    gen_infect_1 and #a >= 3
}

rule gen_infect_5 {
  strings:
    $a = "infect" ascii wide nocase

  condition:
    gen_infect_3 and #a >= 5
}

rule gen_inject_1 {
  strings:
    $a = "inject" ascii wide nocase

  condition:
    $a
}

rule gen_inject_3 {
  strings:
    $a = "inject" ascii wide nocase

  condition:
    gen_infect_1 and #a >= 3
}

rule gen_inject_5 {
  strings:
    $a = "inject" ascii wide nocase

  condition:
    gen_infect_3 and #a >= 5
}

rule gen_hack_1 {
  strings:
    $a = "hack" ascii wide nocase

  condition:
    $a
}

rule gen_hack_3 {
  strings:
    $a = "hack" ascii wide nocase

  condition:
    gen_hack_1 and #a >= 3
}

rule gen_hack_5 {
  strings:
    $a = "hack" ascii wide nocase

  condition:
    gen_hack_3 and #a >= 5
}

rule gen_keylogger_1 {
  strings:
    $a = "keylog" ascii wide nocase

  condition:
    $a
}

rule gen_keylogger_3 {
  strings:
    $a = "keylog" ascii wide nocase

  condition:
    gen_keylogger_1 and #a >= 3
}

rule gen_keylogger_5 {
  strings:
    $a = "keylog" ascii wide nocase

  condition:
    gen_keylogger_5 and #a >= 5
}

rule gen_malware_1 {
  strings:
    $a = "malware" ascii wide nocase

  condition:
    $a
}

rule gen_malware_3 {
  strings:
    $a = "malware" ascii wide nocase

  condition:
    gen_malware_1 and #a >= 3
}

rule gen_malware_5 {
  strings:
    $a = "malware" ascii wide nocase

  condition:
    gen_malware_3 and #a >= 5
}      

rule gen_ransom_1 {
  strings:
    $a = "ransom" ascii wide nocase

  condition:
    $a
}

rule gen_ransom_3 {
  strings:
    $a = "ransom" ascii wide nocase

  condition:
    gen_ransom_1 and #a >= 3
}

rule gen_ransom_5 {
  strings:
    $a = "ransom" ascii wide nocase

  condition:
    gen_ransom_3 and #a >= 5
}

rule gen_rat_1 {
  strings:
    $a = "rat" ascii wide nocase

  condition:
    $a
}

rule gen_rat_3 {
  strings:
    $a = "rat" ascii wide nocase

  condition:
    gen_rat_1 and #a >= 3
}

rule gen_rat_5 {
  strings:
    $a = "rat" ascii wide nocase

  condition:
    gen_rat_3 and #a >= 5
}

rule gen_rootkit_1 {
  strings:
    $a = "rootkit" ascii wide nocase

  condition:
    $a
}

rule gen_rootkit_3 {
  strings:
    $a = "rootkit" ascii wide nocase

  condition:
    gen_rootkit_1 and #a >= 3
}

rule gen_rootkit_5 {
  strings:
    $a = "rootkit" ascii wide nocase

  condition:
    gen_rootkit_3 and #a >= 5
}

rule gen_trojan_1 {
  strings:
    $a = "trojan" ascii wide nocase

  condition:
    #a >= 5
}

rule gen_trojan_3 {
  strings:
    $a = "trojan" ascii wide nocase

  condition:
    gen_trojan_1 and #a >= 3
}

rule gen_trojan_5 {
  strings:
    $a = "trojan" ascii wide nocase

  condition:
    gen_trojan_3 and #a >= 5
}

rule gen_virus_1 {
  strings:
    $a = "virus" ascii wide nocase

  condition:
    $a
}

rule gen_virus_3 {
  strings:
    $a = "virus" ascii wide nocase

  condition:
    gen_virus_1 and #a >= 3
}
      
rule gen_virus_5 {
  strings:
    $a = "virus" ascii wide nocase

  condition:
    gen_virus_3 and #a >= 5
}

rule gen_vuln_1 {
  strings:
    $a = "vuln" ascii wide nocase

  condition:
    $a
}

rule gen_vuln_3 {
  strings:
    $a = "vuln" ascii wide nocase

  condition:
    gen_vuln_1 and #a >= 3
}

rule gen_vuln_5 {
  strings:
    $a = "vuln" ascii wide nocase

  condition:
    gen_vuln_5 and #a >= 5
}

rule gen_worm_1 {
  strings:
    $a = "worm" ascii wide nocase

  condition:
    $a
}

rule gen_worm_3 {
  strings:
    $a = "worm" ascii wide nocase

  condition:
    gen_worm_1 and #a >= 3
}
      
rule gen_worm_5 {
  strings:
    $a = "worm" ascii wide nocase

  condition:
    gen_worm_3 and #a >= 5
}

// ---- Registry rules ---- //

rule registry_1 {
  strings:
    $a = "registry" ascii wide nocase

  condition:
    $a
}

rule registry_3 {
  strings:
    $a = "registry" ascii wide nocase

  condition:
    registry_1 and #a >= 3
}     

rule registry_5 {
  strings:
    $a = "registry" ascii wide nocase

  condition:
    registry_3 and #a >= 5
}

rule registry_run {
  strings:
    $a = "\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide nocase

  condition:
    all of them
}

rule registry_regkey_1 {
  strings:
    $a = "regkey" ascii wide nocase

  condition:
    $a
}

rule registry_regkey_3 {
  strings:
    $a = "regkey" ascii wide nocase

  condition:
    registry_regkey_1 and #a >= 3
}

rule registry_regkey_5 {
  strings:
    $a = "regkey" ascii wide nocase

  condition:
    registry_regkey_3 and #a >= 5
}

rule registry_HKEY_1 {
  strings:
    $a = "HKEY" ascii wide nocase

  condition:
    $a
}

rule registry_HKEY_3 {
  strings:
    $a = "HKEY" ascii wide nocase

  condition:
    registry_HKEY_1 and #a >= 3
}

rule registry_HKEY_5 {
  strings:
    $a = "HKEY" ascii wide nocase

  condition:
    registry_HKEY_3 and #a >= 5
}

rule registry_HKCU_1 {
  strings:
    $a = "HKCU" ascii wide nocase

  condition:
    $a
}

rule registry_HKCU_3 {
  strings:
    $a = "HKCU" ascii wide nocase

  condition:
    registry_HKCU_1 and #a >= 3
}

rule registry_HKCU_5 {
  strings:
    $a = "HKCU" ascii wide nocase

  condition:
    registry_HKCU_3 and #a >= 5
}

rule registry_HKLM_1 {
  strings:
    $a = "HKLM" ascii wide nocase

  condition:
    $a
}

rule registry_HKLM_3 {
  strings:
    $a = "HKLM" ascii wide nocase

  condition:
    registry_HKLM_1 and #a >= 3
}

rule registry_HKLM_5 {
  strings:
    $a = "HKLM" ascii wide nocase

  condition:
    registry_HKLM_3 and #a >= 5
}

// ---- Money ---- //

rule bank_1 {
  strings:
    $a = /(bank)|(banco)/ ascii wide nocase

  condition:
    $a
}

rule bank_3 {
  strings:
    $a = /(bank)|(banco)/ ascii wide nocase

  condition:
    bank_1 and #a >= 3
}

rule bank_5 {
  strings:
    $a = /(bank)|(banco)/ ascii wide nocase

  condition:
    bank_3 and #a >= 5
}

rule paypal_1 {
  strings:
    $a = "paypal" ascii wide nocase

  condition:
    $a
}

rule paypal_3 {
  strings:
    $a = "paypal" ascii wide nocase

  condition:
    paypal_1 and #a >= 3
}

rule paypal_5 {
  strings:
    $a = "paypal" ascii wide nocase

  condition:
    paypal_3 and #a >= 5
}

// ---- TOR ---- //

rule tor_1 {
  strings:
    $a = "tor"

  condition:
    $a
}

rule tor_3 {
  strings:
    $a = "tor"

  condition:
    tor_1 and #a >= 3
}

rule tor_5 {
  strings:
    $a = "tor"

  condition:
    tor_3 and #a >= 5
}

rule tor_onion_1 {
  strings:
    $a = ".onion"

  condition:
    $a
}

rule tor_onion_3 {
  strings:
    $a = ".onion"

  condition:
    tor_onion_1 and #a >= 3
}

rule tor_onion_5 {
  strings:
    $a = ".onion"

  condition:
    tor_onion_3 and #a >= 5
}

// ---- Bitcoin ---- //

rule bitcoin_1 {
  strings:
    $a = "bitcoin" ascii wide nocase

  condition:
    $a
}

rule bitcoin_3 {
  strings:
    $a = "bitcoin" ascii wide nocase

  condition:
    bitcoin_1 and #a >= 3
}

rule bitcoin_5 {
  strings:
    $a = "bitcoin" ascii wide nocase

  condition:
    bitcoin_3 and #a >= 5
}

rule bitcoin_btc_1 {
  strings:
    $a = "btc" ascii wide nocase

  condition:
    $a
}

rule bitcoin_btc_3 {
  strings:
    $a = "btc" ascii wide nocase

  condition:
    bitcoin_btc_1 and #a >= 3
}

rule bitcoin_btc_5 {
  strings:
    $a = "btc" ascii wide nocase

  condition:
    bitcoin_btc_3 and #a >= 5
}      

rule bitcoin_blockchain_1 {
  strings:
    $a = "blockchain" ascii wide nocase

  condition:
    $a
}

rule bitcoin_blockchain_3 {
  strings:
    $a = "blockchain" ascii wide nocase

  condition:
    bitcoin_blockchain_1 and #a >= 3
}      

rule bitcoin_blockchain_5 {
  strings:
    $a = "blockchain" ascii wide nocase

  condition:
    bitcoin_blockchain_3 and #a >= 5
}

rule bitcoin_blockr_1 {
  strings:
    $a = "blockr" ascii wide nocase

  condition:
    $a 
}

rule bitcoin_blockr_3 {
  strings:
    $a = "blockr" ascii wide nocase

  condition:
    bitcoin_blockr_1 and #a >= 3
}

rule bitcoin_blockr_5 {
  strings:
    $a = "blockr" ascii wide nocase

  condition:
    bitcoin_blockr_3 and #a >= 5
}

rule bitcoin_bitmessage_1 {
  strings:
    $a = "bitmessage" ascii wide nocase

  condition:
    $a
}

rule bitcoin_bitmessage_3 {
  strings:
    $a = "bitmessage" ascii wide nocase

  condition:
    bitcoin_bitmessage_1 and #a >= 3
}

rule bitcoin_bitmessage_5 {
  strings:
    $a = "bitmessage" ascii wide nocase

  condition:
    bitcoin_bitmessage_3 and #a >= 5
}    

/*
rule bitcoin_wallet {
  strings:
    $a1 = "bitcoin" ascii wide nocase
    $a2 = "btc" ascii wide nocase
    $a3 = "blockchain" ascii wide nocase
    $a4 = "blockr" ascii wide nocase
    $a5 = "wallet" ascii wide nocase

    $b = /\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}/ fullword ascii wide nocase

  condition:
    1 of ($a*) and $b
}*/

// ---- Ransomware note ---- //

rule ransom_delete_1 {
  strings:
    $a = "delete" ascii wide nocase

  condition:
    $a
}

rule ransom_delete_3 {
  strings:
    $a = "delete" ascii wide nocase

  condition:
    ransom_delete_1 and #a >= 3
}

rule ransom_delete_5 {
  strings:
    $a = "delete" ascii wide nocase

  condition:
    ransom_delete_3 and #a >= 5
}

rule ransom_pay_1 {
  strings:
    $a = "pay" ascii wide nocase

  condition:
    $a
}

rule ransom_pay_3 {
  strings:
    $a = "pay" ascii wide nocase

  condition:
    ransom_pay_1 and #a >= 3
}

rule ransom_pay_5 {
  strings:
    $a = "pay" ascii wide nocase

  condition:
    ransom_pay_3 and #a >= 5	
}

rule ransom_lock_1 {
  strings:
    $a = "lock" ascii wide nocase

  condition:
    $a
}

rule ransom_lock_3 {
  strings:
    $a = "lock" ascii wide nocase

  condition:
    ransom_lock_1 and #a >= 3
}

rule ransom_lock_5 {
  strings:
    $a = "lock" ascii wide nocase

  condition:
    ransom_lock_3 and #a >= 5
}

// ---- Network ---- //

rule network_1 {
  strings:
    $a = "network" ascii wide nocase

  condition:
    $a
}

rule network_3 {
  strings:
    $a = "network" ascii wide nocase

  condition:
    network_1 and #a >= 3
}

rule network_5 {
  strings:
    $a = "network" ascii wide nocase

  condition:
    network_3 and #a >= 5
}

rule network_cnc_1 {
  strings:
    $a = "c&c" fullword ascii wide nocase
    $b = "cnc" fullword ascii wide nocase
    $c = "c2" fullword ascii nocase

  condition:
    any of them
}

rule network_cnc_3 {
  strings:
    $a = "c&c" fullword ascii wide nocase
    $b = "cnc" fullword ascii wide nocase
    $c = "c2" fullword ascii nocase

  condition:
    network_cnc_1 and #a + #b + #c >= 3
}

rule network_cnc_5 {
  strings:
    $a = "c&c" fullword ascii wide nocase
    $b = "cnc" fullword ascii wide nocase
    $c = "c2" fullword ascii nocase

  condition:
    network_cnc_3 and #a + #b + #c >= 5
}

rule network_exfil_1 {
  strings:
    $a = "exfil" ascii wide nocase

  condition:
    $a
}

rule network_exfil_3 {
  strings:
    $a = "exfil" ascii wide nocase

  condition:
    network_exfil_1 and #a >= 3
}

rule network_exfil_5 {
  strings:
    $a = "exfil" ascii wide nocase

  condition:
    network_exfil_3 and #a >= 5
}

rule network_connect_1 {
  strings:
    $a = "connect" ascii wide nocase

  condition:
    $a
}

rule network_connect_3 {
  strings:
    $a = "connect" ascii wide nocase

  condition:
    network_connect_1 and #a >= 3
}

rule network_connect_5 {
  strings:
    $a = "connect" ascii wide nocase

  condition:
    network_connect_3 and #a >= 5
}

rule network_ping_1 {
  strings:
    $a = "ping" ascii wide nocase

  condition:
    $a
}

rule network_ping_3 {
  strings:
    $a = "ping" ascii wide nocase

  condition:
    network_ping_1 and #a >= 3
}

rule network_ping_5 {
  strings:
    $a = "ping" ascii wide nocase

  condition:
    network_ping_3 and #a >= 5
}

rule network_socket_1 {
  strings:
    $a = "socket" ascii wide nocase

  condition:
    $a
}

rule network_socket_3 {
  strings:
    $a = "socket" ascii wide nocase

  condition:
    network_socket_1 and #a >= 3
}

rule network_socket_5 {
  strings:
    $a = "socket" ascii wide nocase

  condition:
    network_socket_3 and #a >= 5
}

rule network_eth0_1 {
  strings:
    $a = "eth0" ascii wide nocase

  condition:
    $a
}

rule network_eth0_3 {
  strings:
    $a = "eth0" ascii wide nocase

  condition:
    network_eth0_1 and #a >= 3
}

rule network_eth0_5 {
  strings:
    $a = "eth0" ascii wide nocase

  condition:
    network_eth0_3 and #a >= 5
}

// ---- Crypto ---- //

rule cipher_1 {
  strings:
    $a = "cipher" ascii wide nocase

  condition:
    $a
}

rule cipher_3 {
  strings:
    $a = "cipher" ascii wide nocase

  condition:
    cipher_1 and #a >= 3
}

rule cipher_5 {
  strings:
    $a = "cipher" ascii wide nocase

  condition:
    cipher_3 and #a >= 5
}

rule crypto_1 {
  strings:
    $a = "crypt" ascii wide nocase

  condition:
    #a >= 5
}

rule crypto_3 {
  strings:
    $a = "crypt" ascii wide nocase

  condition:
    crypto_1 and #a >= 3
}

rule crypto_5 {
  strings:
    $a = "crypt" ascii wide nocase

  condition:
    crypto_3 and #a >= 5
}

rule xor_1 {
  strings:
    $a = "xor" ascii wide nocase

  condition:
    $a
}

rule xor_3 {
  strings:
    $a = "xor" ascii wide nocase

  condition:
    xor_1 and #a >= 3
}

rule xor_5 {
  strings:
    $a = "xor" ascii wide nocase

  condition:
    xor_3 and #a >= 5
}

rule crypto_aes {
  strings:
    $a = "aes" ascii wide nocase
    $aes1 = /\baes.128/ fullword ascii wide nocase
    $aes2 = /\baes.256/ fullword ascii wide nocase

  condition:
    $a and 1 of ($aes*)
}

rule crypto_rsa {
  strings:
    $a = "rsa" ascii wide nocase
    $rsa1 = /\brsa.2048/ fullword ascii wide nocase
    $rsa2 = /\brsa.4096/ fullword ascii wide nocase

  condition:
    $a and 1 of ($rsa*)
}

rule crypto_aes_1 {
  strings:
    $a = "aes" ascii wide nocase

  condition:
    $a
}

rule crypto_aes_3 {
  strings:
    $a = "aes" ascii wide nocase

  condition:
    crypto_aes_1 and #a >= 3
}

rule crypto_aes_5 {
  strings:
    $a = "aes" ascii wide nocase

  condition:
    crypto_aes_3 and #a >= 5
}

rule crypto_rsa_1 {
  strings:
    $a = "rsa" ascii wide nocase

  condition:
    $a
}

rule crypto_rsa_3 {
  strings:
    $a = "rsa" ascii wide nocase

  condition:
    crypto_rsa_1 and #a >= 3
}

rule crypto_rsa_5 {
  strings:
    $a = "rsa" ascii wide nocase

  condition:
    crypto_rsa_3 and #a >= 5
}

// ---- Packing ---- //

rule packer_upx_1 {
  strings:
    $a = "upx" ascii wide nocase

  condition:
    $a
}

rule packer_upx_3 {
  strings:
    $a = "upx" ascii wide nocase

  condition:
    packer_upx_1 and #a >= 3
}

rule packer_upx_5 {
  strings:
    $a = "upx" ascii wide nocase

  condition:
    packer_upx_3 and #a >= 5
}    

rule packer_nsis_1 {
  strings:
    $a = "nsis" ascii wide nocase

  condition:
    $a
}

rule packer_nsis_3 {
  strings:
    $a = "nsis" ascii wide nocase

  condition:
    packer_nsis_1 and #a >= 3
}

rule packer_nsis_5 {
  strings:
    $a = "nsis" ascii wide nocase

  condition:
    packer_nsis_3 and #a >= 5
}

// ---- Mutex ---- //

rule mutex_1 {
  strings:
    $a = "mutex" ascii wide nocase

  condition:
    $a
}

rule mutex_3 {
  strings:
    $a = "mutex" ascii wide nocase

  condition:
    mutex_1 and #a >= 3
}

rule mutex_5 {
  strings:
    $a = "mutex" ascii wide nocase

  condition:
    mutex_3 and #a >= 5
}

rule semaphore_1 {
  strings:
    $a = "semaphore" ascii wide nocase

  condition:
    $a
}

rule semaphore_3 {
  strings:
    $a = "semaphore" ascii wide nocase

  condition:
    semaphore_1 and #a >= 3
}

rule semaphore_5 {
  strings:
    $a = "semaphore" ascii wide nocase

  condition:
    semaphore_3 and #a >= 5    
}

// ---- Other ---- //

rule other_loadlibrary {
  strings:
    $a = "loadlibrary" ascii wide nocase

  condition:
    all of them
}

rule keystroke_1 {
  strings:
    $a = "keystroke" ascii wide nocase

  condition:
    $a
}

rule keystroke_3 {
  strings:
    $a = "keystroke" ascii wide nocase

  condition:
    keystroke_1 and #a >= 3
}

rule keystroke_5 {
  strings:
    $a = "keystroke" ascii wide nocase

  condition:
    keystroke_3 and #a >= 5
}

rule steal_1 {
  strings:
    $a = "steal" ascii wide nocase

  condition:
    $a
}

rule steal_3 {
  strings:
    $a = "steal" ascii wide nocase

  condition:
    steal_1 and #a >= 3
}

rule steal_5 {
  strings:
    $a = "steal" ascii wide nocase

  condition:
    steal_3 and #a >= 5
}

rule persist_1 {
  strings:
    $a = "persist" ascii wide nocase

  condition:
    $a
}

rule persist_3 {
  strings:
    $a = "persist" ascii wide nocase

  condition:
    persist_1 and #a >= 3
}

rule persist_5 {
  strings:
    $a = "persist" ascii wide nocase

  condition:
    persist_3 and #a >= 5
}

rule irc_1 {
  strings:
    $a = "irc" ascii wide nocase

  condition:
    $a
}

rule irc_3 {
  strings:
    $a = "irc" ascii wide nocase

  condition:
    irc_1 and #a >= 3
}

rule irc_5 {
  strings:
    $a = "irc" ascii wide nocase

  condition:
    irc_3 and #a >= 5
}

rule shell_1 {
  strings:
    $a = "shell" ascii wide nocase

  condition:
    $a
}

rule shell_3 {
  strings:
    $a = "shell" ascii wide nocase

  condition:
    shell_1 and #a >= 3
}

rule shell_5 {
  strings:
    $a = "shell" ascii wide nocase

  condition:
    shell_3 and #a >= 5
}
      

//shell