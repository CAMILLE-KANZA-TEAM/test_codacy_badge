<?php

	class UserController extends BaseController {

        /**
         * @var SessionManager
         */
        private $sessionManager;

		public function __construct($httpRequest, $config)
        {
            parent::__construct($httpRequest, $config);
            $this->sessionManager = new SessionManager();
        }

        public function Login() {
			$this->View("login");
		}
		
		public function Authenticate() {

			$login = $this->_httpRequest->getRequest()["login"];
			$password = $this->_httpRequest->getRequest()["password"];
			$user = $this->UserManager->getByMail($login);

			if(password_verify($password, $user->password)) {
                $this->sessionManager->set('Connected', $user->email);
                $this->sessionManager->set('Valid', $user->getValid());

						//$_SESSION['Connected'] = $user->email;
						//$_SESSION['Valid'] = $user->getValid();
						header("Location: /");
						exit();
			}else {
				header("Location: /Login");
			}
		}

		public function Registration() {
			
			$tokenCsrf = md5(uniqid('csrf_'));

			$form = new Form();
			$form->add('pseudo', "Pseudo", [
				function($value) {
					return [
						"assertion" => $value !== "",
						"message" => "Votre champ ne doit pas êtres vide." 
					];
			}]);
			$form->add('email', "Adresse Email", [
				function($value) {
					return [
						"assertion" => $value !== "",
						"message" => "Votre champ ne doit pas êtres vide." 
					];
				},
				function($value) {
					return [
						"assertion" => filter_var($value, FILTER_VALIDATE_EMAIL) == true,
						"message" => "Votre email n'est pas valide."
					];
				}
			]);
			$form->add('password', "Mot de passe");
			$form->handle($this->_httpRequest);
			if($form->isSubmitted() && $form->isValid()) {
				$requestMethode = $_SERVER["REQUEST_METHOD"];
                //$sessionToken = $_SESSION['_token'];
                $sessionToken = $this->sessionManager->get('_token');

				if(isset($requestMethode) && $requestMethode === "POST") {
					if( $sessionToken === $_POST["_token"]) {
						$password = $_POST['password'];
						$pseudo = $_POST['pseudo'];
						$email = $_POST['email'];

						$passwordHash = password_hash($password, PASSWORD_DEFAULT);
						$this->UserManager->addUser($pseudo, $passwordHash, $email);
						header("Location: /Login");
						exit();
					} else {
						echo "<div class='alert alert-danger'>CSRF invalid</div>";
					}
				}
			}

			//$_SESSION['_token'] = $tokenCsrf;
            $this->sessionManager->set('_token', $tokenCsrf);

			$this->addParam("form", $form);
			$this->View("registration");
		}

		public function Logout() {
			//unset($_SESSION['Connected']);
            $this->sessionManager->delete('Connected');
			header("Location: /");
		}

		/* Administration user */

        public function UserList() {
            $users = $this->UserManager->getListUsers();
            
            $this->addParam("users", $users);
            $this->View("admin/userlist");
        }

        public function UserValid($id) {
			
			$this->UserManager->validUser($id);

			//$_SESSION['message'] = "<div class='alert alert-success'>l'Utilisateur vient d'êtres validé.</div>";
            $this->sessionManager->set('message', "<div class='alert alert-success'>l'Utilisateur vient d'êtres validé.</div>");
			header("Location: /admin/user/list");
			exit();
		}

		public function UserDevalid($id) {
			
			$this->UserManager->devalidUser($id);

			//$_SESSION['message'] = "<div class='alert alert-success'>l'Utilisateur vient d'êtres dévalidé.</div>";
            $this->sessionManager->set('message', "<div class='alert alert-success'>l'Utilisateur vient d'êtres dévalidé.</div>");
			header("Location: /admin/user/list");
			exit();
		}
	}