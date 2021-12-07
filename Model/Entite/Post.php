<?php

	class Post {
        
		private $id;
		public $title;
		public $chapo;
		public $content;
		public $image;
		public $lastModificationDate;
		
		public function __construct() {
			
		}

		public function getId() {
			return $this->id;
		}

		public function getTitle() {
			return $this->title;
		}

		public function setTitle($title) {
			$this->title = $title;

			return $this;
		}

		public function getChapo() {
			return $this->chapo;
		}

		public function setChapo($chapo) {
			$this->chapo = $chapo;

			return $this;
		}

		public function getContent() {
			return $this->content;
		}

		public function setContent($content) {
			$this->content = $content;

			return $this;
		}

		public function getImage() {
			return $this->image;
		}

		public function setImage($image) {
			$this->image = $image;

			return $this;
		}

		public function getLastModificationDate() {
			return $this->lastModificationDate;
		}

		public function setLastModificationDate(string $lastModificationDate) {
			$this->lastModificationDate = $lastModificationDate;

			return $this;
		}
	}