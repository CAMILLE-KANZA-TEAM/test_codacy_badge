<?php

	class BaseController {

		protected $_httpRequest;
		private $_param;
		private $_config;
		
		public function __construct($httpRequest, $config) {
			$this->_httpRequest = $httpRequest;
			$this->_config = $config;
			$this->_param = array();
			$this->addParam("httprequest", $this->_httpRequest);
			$this->addParam("config", $this->_config);
			$this->bindManager();
		}
		
		protected function view($filename) {
			if(file_exists("View/" . $this->_httpRequest->getRoute()->getController() . "/" . $filename . ".php")) {
				ob_start();
				extract($this->_param);
				$messageTemp = $_SESSION['message'];
				if (isset($messageTemp)) {
					$message = $_SESSION['message'];
					unset($_SESSION['message']);
				}
				include("View/" . $this->_httpRequest->getRoute()->getController() . "/" . $filename . ".php");
				$content = ob_get_clean();
				include("View/layout.php");
			}else {
				throw new ViewNotFoundException();	
			}
		}
		
		public function bindManager() {
			foreach($this->_httpRequest->getRoute()->getManager() as $manager) {
				$this->$manager = new $manager($this->_config->database);
			}
		}

        public function addParam($name, $value) {
			$this->_param[$name] = $value;
		}

		public function addCss($file) {
			$this->_fileManager->addCss($file);
		}
		
		public function addJs($file) {
			$this->_fileManager->addJs($file);
		}
	}