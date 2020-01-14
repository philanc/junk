
# 200113  removed $redir, added echo $date when restart

# rx:  all output goes to stdout
# rxd: stdout and stderr go to rxd.log

# $(date ...)  :: server date (should be UTC)

logfile=rxd.log

echo "$(date -Iseconds) rxd.sh (pid=$$) started"

# to kill rxd.sh process _and_ lua process below,
# do 'kill $(pkill -P 123) 123' where 123 is the rxd.sh pid
# 'kill 123' leaves the lua process alive

# ^C must interrupt the lua process below and this rxd.sh process
### hmmm, no.
### trap 'exit 2' INT

while /bin/true ;  do
	./slua rx.lua serve   2>&1
	status="$?" 
	#  restart if exitcode is 0 or 143 (SIGTERM  ::  15 + 128)
	#  (restart when interrupted with default kill:  kill <server-pid>)
	if [ $status != "0" -a $status != "143" ] ; then 
		break
	fi
	echo "$(date -Iseconds) server has exited. sleep 1, then restart."
	sleep 1
done

echo "$(date -Iseconds) rxd.lua exited with code $status" 
exit $status




