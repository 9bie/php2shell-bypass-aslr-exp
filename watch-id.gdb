set pagination off
set auto-load safe-path /
set confirm off
set debuginfod enabled off
set $pbase=(char *)&ps_globals
set $id=*(void **)($pbase+16)
printf "WATCH_ID=%p SEND_COOKIE=%u\n", $id, *(unsigned char *)($pbase+350)
watch *(unsigned long long *)$id
commands
  silent
  printf "\nSTALE_ID_WRITE value=0x%lx\n", *(unsigned long long *)$id
  bt 14
  x/8gx $id
  continue
end
continue
