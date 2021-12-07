<?php

	class Comment {
        
		private $id;
		public $publicationDate;
		public $content;
		public $valid;
		
		public function __construct() {
			
		}

		public function getId() {
			return $this->id;
		}

		public function getPublicationDate() {
			return $this->publicationDate;
		}

		public function setPublicationDate($publicationDate) {
			$this->publicationDate = $publicationDate;

			return $this;
		}

		public function getContent() {
			return $this->content;
		}

		public function setContent($content) {
			$this->content = $content;

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