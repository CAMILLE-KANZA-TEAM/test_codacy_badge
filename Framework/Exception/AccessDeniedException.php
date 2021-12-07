<?php

	class AccessDeniedException extends Exception {
		public function __construct($message = "Unauthorized access") {
			parent::__construct($message, "0001");
		}
	}