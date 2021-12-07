<?php

	class EmailController extends BaseController {

        /* Evoie Email de contact */

        public function EmailContact() {

            if(isset($_POST['submit'])){
                $emailUser = $_ENV['emailUser'];
                $emailPassword = $_ENV['emailPassword'];
                $email = $_POST['email'];
                $nom = $_POST['nom'];
                $prenom = $_POST['prenom'];
                $emailMessage = $_POST['message'];
                try {
                    $transport = (new Swift_SmtpTransport('smtp.googlemail.com', 465, 'ssl'))
                      ->setUsername($emailUser)
                      ->setPassword($emailPassword)
                    ;
                 
                    $mailer = new Swift_Mailer($transport);
                 
                    $message = (new Swift_Message('Contact'))
                      ->setFrom([$emailUser => $prenom])
                      ->setReplyTo([$email])
                      ->setTo([$emailUser])
                      ->setBody($nom.' '.$prenom.' vous écrit:<br><br>'.$emailMessage.'<br><br> Vous pouvez lui répondre à cette adresse email: '.$email)
                      ->setContentType('text/html')
                    ;
                 
                    $mailer->send($message);
                 
                    $_SESSION['message'] = "<div class='alert alert-success'>Le mail à bien été envoyer, vous serez contacter dans les plus bref délais.</div>";
                } catch(Exception $e) {
                    $_SESSION['message'] = "<div class='alert alert-danger'>".$e->getMessage()."</div>";
                }
            }
            
            header("Location: /");
        }

    }