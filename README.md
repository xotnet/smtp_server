# good smtp server

! Require OpenSSL, network in main file made for linux 
! dkim.key required in this path for encryption and signing

main function: send_email(char* dest_email, char* message, char* subject, char* src_email);
main function usage example: send_email("my_friend@proton.me", "Hello, how are you", "Talk", "john@rootc.org") - rootc.org DNS contain dkim record and spf record
