<?php

    class HttpRequest {

        private $_url;
        private $_method;
        private $_param;
		private $_route;
		private $_request = [];

        public function __construct($url = null, $method = null) {
            $post = $_POST;

            $this->_url = (is_null($url))?$_SERVER['REQUEST_URI']:$url;
			$this->_method = (is_null($method))?$_SERVER['REQUEST_METHOD']:$method;
			$this->_param = array();
			$this->_request = $post;
        }

        public function getUrl() {
            return $this->_url;
        }

        public function getMethod() {
            return $this->_method;
        }

        public function getParams() {
            return $this->_params;
        }

        public function setRoute($route) {
          $this->_route = $route;	
        }

        public function getRequest() {
            return $this->_request;	
        }

        public function bindParam() {
			switch($this->_method) {
				case "GET":
                case "POST":
                case "DELETE":
                    foreach($this->_route->getParam() as $param) {
						if(isset($_GET[$param])) {
                            $getParam = $_GET[$param];
							$this->_param[] = $getParam;
						}
					}
			}
		}

        public function getRoute() {
			return $this->_route;	
		}

        public function getParam() {
			return $this->_param;	
		}

        public function run($config) {
            $this->bindParam();
            $this->_route->run($this, $config);
        }

        public function addParam($value) {
            $this->_param[] = $value;
        }
    }