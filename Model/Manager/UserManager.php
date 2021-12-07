<?php

	class UserManager extends BaseManager {

		public function __construct($datasource) {
			parent::__construct("user", "User", $datasource);	
		}

        public function getByMail($mail) {
			$req = $this->_bdd->prepare("SELECT * FROM user WHERE email=?");
			$req->execute(array($mail));
			$req->setFetchMode(PDO::FETCH_CLASS|PDO::FETCH_PROPS_LATE, "User");
			return $req->fetch();
		}

		public function addUser($pseudo, $password, $login) {
			$roles = "['ROLE_USER']";
			$valid = 0;
			
			$req = $this->_bdd->prepare('INSERT INTO user (pseudo, password, email, roles, valid) VALUES (:pseudo, :password, :email, :roles, :valid)');

			$req->bindParam(':pseudo', $pseudo);
			$req->bindParam(':password', $password);
			$req->bindParam(':email', $login);
			$req->bindParam(':roles', $roles);
			$req->bindParam(':valid', $valid);

			$req->execute();
		}

		public function getListUsers() {
			$req = $this->_bdd->prepare("SELECT * FROM user");
			$req->execute();
			return $req->fetchAll(PDO::FETCH_CLASS, 'User');
		}

		public function validUser($id) {
			$valid = "1";

			$req = $this->_bdd->prepare('UPDATE user SET valid = :valid WHERE id = :id');

			$req->bindParam(':valid', $valid);
			$req->bindParam(':id', $id);

			$req->execute();
		}

		public function devalidUser($id) {
			$valid = "0";

			$req = $this->_bdd->prepare('UPDATE user SET valid = :valid WHERE id = :id');

			$req->bindParam(':valid', $valid);
			$req->bindParam(':id', $id);

			$req->execute();
		}
	}