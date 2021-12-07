<?php

	class CommentManager extends BaseManager {

		public function __construct($datasource) {
			parent::__construct("comment", "Comment", $datasource);	
		}

		public function getListComments() {
			$req = $this->_bdd->prepare("SELECT * FROM comment");
			$req->execute();
			return $req->fetchAll(PDO::FETCH_CLASS, 'Comment');
		}

        public function getComments($id) {
			$valid = "1";

			$req = $this->_bdd->prepare("SELECT * FROM comment WHERE post_id = :post AND valid = :valid");
			
			$req->bindParam(':post', $id);
			$req->bindParam(':valid', $valid);

			$req->execute();

			$req->setFetchMode(PDO::FETCH_CLASS|PDO::FETCH_PROPS_LATE, "Comment");
			return $req->fetchAll();
		}

		public function addComment($content, $id) {
			$valid = 0;
			$date = date("Y-m-d H:i:s");
			
			$req = $this->_bdd->prepare('INSERT INTO comment (publicationDate, content, valid, post_id) VALUES (:publicationDate, :content, :valid, :post_id)');

			$req->bindParam(':publicationDate', $date);
			$req->bindParam(':content', $content);
			$req->bindParam(':valid', $valid);
			$req->bindParam(':post_id', $id);

			$req->execute();
		}

		public function deleteComment($id) {
			$req = $this->_bdd->prepare('DELETE FROM comment WHERE id=?');
			
			$req->execute(array($id));
			return $req->execute();

		}

		public function validComment($id) {
			$valid = "1";

			$req = $this->_bdd->prepare('UPDATE comment SET valid = :valid WHERE id = :id');

			$req->bindParam(':valid', $valid);
			$req->bindParam(':id', $id);

			$req->execute();
		}

		public function devalidComment($id) {
			$valid = "0";

			$req = $this->_bdd->prepare('UPDATE comment SET valid = :valid WHERE id = :id');

			$req->bindParam(':valid', $valid);
			$req->bindParam(':id', $id);

			$req->execute();
		}
	}