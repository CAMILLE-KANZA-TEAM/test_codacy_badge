<?php

	class CommentController extends BaseController {

        /* Administration Comment */

        public function CommentList() {
            $comments = $this->CommentManager->getListComments();
            
            $this->addParam("comments", $comments);
            $this->View("admin/commentlist");
        }

        public function CommentDelete($id) {

			$this->CommentManager->deleteComment($id);

			$_SESSION['message'] = "<div class='alert alert-success'>Le commentaire a bien été supprimer.</div>";
			header("Location: /admin/comment/list");
			exit();
		}

        public function CommentValid($id) {

			$this->CommentManager->validComment($id);

			$_SESSION['message'] = "<div class='alert alert-success'>Le commentaire vient d'êtres validé.</div>";
			header("Location: /admin/comment/list");
			exit();
		}

        public function CommentDevalid($id) {

			$this->CommentManager->devalidComment($id);

			$_SESSION['message'] = "<div class='alert alert-success'>Le commentaire vient d'êtres dévalidé.</div>";
			header("Location: /admin/comment/list");
			exit();
		}

    }