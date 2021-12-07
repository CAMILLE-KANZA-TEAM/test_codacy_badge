<?php

	class User {
        
		private $id;
		public $pseudo;
		public $email;
		public $password;
		public $valid;
		
		public function __construct() {
			
		}

		public function getId() {
			return $this->id;
		}

		public function getPseudo() {
			return $this->pseudo;
		}

		public function setPseudo($pseudo) {
			$this->pseudo = $pseudo;

			return $this;
		}

		public function getEmail() {
			return $this->email;
		}

		public function setEmail($email) {
			$this->email = $email;

			return $this;
		}

		public function getPassword() {
			return $this->password;
		}

		public function setPassword($password) {
			$this->password = $password;

			return $this;
		}

		public function getValid() {
			return $this->valid;
		}

		public function setValid($valid) {
			$this->valid = $valid;

			return $this;
		}
	}