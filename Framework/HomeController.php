<?php

	class HomeController extends BaseController {

		public function Home() {
			$this->view("home");
		}

		public function HomeAdmin() {
			$this->view("home-admin");
		}
	}