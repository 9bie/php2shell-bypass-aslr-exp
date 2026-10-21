set pagination off
set auto-load safe-path /
set confirm off
handle SIGPIPE nostop noprint pass
break _zend_bailout
commands
  silent
  printf "\n=== bailout ===\n"
  set $pbase=(char *)&ps_globals
  printf "ps.id=%p send_cookie=%u http_session_vars=%p\n", *(void **)($pbase+16), *(unsigned char *)($pbase+350), *(void **)($pbase+360)
  if *(void **)($pbase+16) != 0
    x/8gx *(void **)($pbase+16)
  end
  bt 14
  continue
end
continue
