<?php

	class PostController extends BaseController {
		
        public function ListPost() {
			$posts = $this->PostManager->getPosts();
            
			$this->addParam("posts", $posts);
			$this->View("listpost");
        }

		public function Post($id) {
			$post = $this->PostManager->getPost($id);
			$comments = $this->CommentManager->getComments($id);

			$form = new Form();
			$form->add('content', "Content", [
				function($value) {
					return [
						"assertion" => $value !== "",
						"message" => "Votre champ ne doit pas êtres vide."
					];
			}]);
			$form->handle($this->_httpRequest);
			if($form->isSubmitted() && $form->isValid()) {
				$this->CommentManager->addComment($form->fields['content']['value'], $id);
				header("Location: /post?id=". $id);
				exit();
			}

			$this->addParam("form", $form);
			$this->addParam("post", $post);
			$this->addParam("comments", $comments);
			$this->View("post");
		}

		/* Administration Post */

		public function PostList() {
			$posts = $this->PostManager->getPosts();
            
			$this->addParam("posts", $posts);
			$this->View("admin/postlist");
        }

		public function PostAdd() {
            
			$tokenCsrf = md5(uniqid('csrf_'));

			$form = new Form();
			$form->add('title', "Titre", [
				function($value) {
					return [
						"assertion" => $value !== "",
						"message" => "Votre champ ne doit pas êtres vide."
					];
			}]);
			$form->add('chapo', "Extrait", [
				function($value) {
					return [
						"assertion" => $value !== "",
						"message" => "Votre champ ne doit pas êtres vide."
					];
			}]);
			$form->add('content', "Contenu", [
				function($value) {
					return [
						"assertion" => $value !== "",
						"message" => "Votre champ ne doit pas êtres vide."
					];
			}]);
			$form->add('image', "Image", [
				function($value) {
					return [
						"assertion" => $value !== "",
						"message" => "Votre champ ne doit pas êtres vide."
					];
			}]);
			$form->handle($this->_httpRequest);
			if($form->isSubmitted() && $form->isValid()) {

				if(isset($_SERVER["REQUEST_METHOD"]) && $_SERVER["REQUEST_METHOD"] === "POST") {
					$sessionToken = $_SESSION['_token'];

					if($sessionToken === $_POST["_token"]) {

						if(isset($_FILES['image'])){
							$tmpName = $_FILES['image']['tmp_name'];
							$fileName = $_FILES['image']['name'];
							$size = $_FILES['image']['size'];
							$type = $_FILES['image']['type'];
							$error = $_FILES['image']['error'];

							$maxSize = 400000000;

							if($size <= $maxSize && $error == 0 && ($type == "image/jpg" || $type == "image/jpeg" || $type == "image/png")){
								move_uploaded_file($tmpName, './Uploads/'.$fileName);
							} else {
								$_SESSION['message'] = "<div class='alert alert-danger'>Fichier non valide.</div>";
								exit();
							}
						}
						
						$this->PostManager->addPost($form->fields['title']['value'], $form->fields['chapo']['value'], $form->fields['content']['value'], $_FILES['image']['name']);
						$_SESSION['message'] = "<div class='alert alert-success'>Le post à bien été ajouter.</div>";
						header("Location: /admin/post/list");
						exit();
					} else {
						$_SESSION['message'] = "<div class='alert alert-danger'>CSRF invalid</div>";
					}
				}
			}
			
			$_SESSION['_token'] = $tokenCsrf;

			$this->addParam("form", $form);
			$this->View("admin/postadd");
        }

		public function PostEdit($id) {
			
			$tokenCsrf = md5(uniqid('csrf_'));
			
			$post = $this->PostManager->getPost($id);

			$form = new Form();
			$form->add('title', "Titre", [
				function($value) {
					return [
						"assertion" => $value !== "",
						"message" => "Votre champ ne doit pas êtres vide."
					];
			}], $post->getTitle());
			$form->add('chapo', "Extrait", [
				function($value) {
					return [
						"assertion" => $value !== "",
						"message" => "Votre champ ne doit pas êtres vide."
					];
			}], $post->getChapo());
			$form->add('content', "Contenu", [
				function($value) {
					return [
						"assertion" => $value !== "",
						"message" => "Votre champ ne doit pas êtres vide."
					];
			}], $post->getContent());
			$form->add('image', "Image", [
				function($value) {
					return [
						"assertion" => $value !== "",
						"message" => "Votre champ ne doit pas êtres vide."
					];
			}], $post->getImage());
			$form->handle($this->_httpRequest);
			if($form->isSubmitted() && $form->isValid()) {

				if($_SERVER["REQUEST_METHOD"] === "POST") {
					if($_SESSION['_token'] === $_POST["_token"]) {

						if(isset($_FILES['image']) && !$_FILES['image']['size'] == 0){
							$tmpName = $_FILES['image']['tmp_name'];
							$fileName = $_FILES['image']['name'];
							$size = $_FILES['image']['size'];
							$type = $_FILES['image']['type'];
							$error = $_FILES['image']['error'];

							$maxSize = 400000000;

							if($size <= $maxSize && $error == 0 && ($type == "image/jpg" || $type == "image/jpeg" || $type == "image/png")){
								unlink('./Uploads/'.$form->fields['image']['value']);
								move_uploaded_file($tmpName, './Uploads/'.$fileName);
							} else {
								$_SESSION['message'] = "<div class='alert alert-danger'>Fichier non valide.</div>";
								header("Location: /admin/post/edit?id=".$post->getId());
								exit();
							}
						} else {
							$fileName = $form->fields['image']['value'];
						}

						$this->PostManager->editPost($id, $form->fields['title']['value'], $form->fields['chapo']['value'], $form->fields['content']['value'], $fileName);
						$_SESSION['message'] = "<div class='alert alert-success'>Le post à bien été modifier.</div>";
						
						header("Location: /admin/post/list");
						exit();
					} else {
						$_SESSION['message'] = "<div class='alert alert-danger'>CSRF invalid</div>";
					}
				}
			}

			$_SESSION['_token'] = $tokenCsrf;

			$this->addParam("form", $form);
			$this->View("admin/postedit");
        }

		public function PostDelete($id) {

			$this->PostManager->deletePost($id);

			$_SESSION['message'] = "<div class='alert alert-success'>Le post à bien été supprimer.</div>";
			header("Location: /admin/post/list");
			exit();
		}
	}