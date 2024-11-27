void Config::epoll_loop(){
	int event_count, i;
	int epoll_fd = epoll_create(1);
	char read_buffer[11];
	if (epoll_fd == -1){
		std::cerr << "Error in creating epoll" << std::endl;
		return ; //exit?
	}
	struct epoll_event ev, events[5];
    ev.events = EPOLLIN;  // Event to monitor for input (readable)
    ev.data.fd = 0;  // File descriptor for stdin (fd = 0)
/*returns a file descriptor that can be used for monitoring multiple I/O events, 
does not accept any flags and its size parameter is ignored.*/
	if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, 0, &ev)){ //&ev - lets us know that we are
	//looking only for input events
		std::cout << "Error in adding fd 0 to epoll" << std::endl;
		close(epoll_fd);
		exit(1); //return ?
	}
	while(1){
		event_count = epoll_wait(epoll_fd, events, 5, 30000); //30000 - every 30 sec
		for (i = 0; i < event_count; i++) {
			size_t bytes_read = read(events[i].data.fd, read_buffer, 10);
			read_buffer[bytes_read] = '\0';
			if(!strncmp(read_buffer, "stop\n", 5))
				break;
		}
	}
	close(epoll_fd);

}
