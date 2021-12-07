<?php
class SessionManager
{
    /**
     * @var Array
     */
    private $vars;

    /**
     *
     */
    public function __construct() {
        $this->vars = $_SESSION;
    }

    /**
     * @param $key
     * @param $value
     * @return void
     */
    public function set($key, $value){
        $_SESSION[$key] = $value;
        $this->vars = $_SESSION;
    }

    /**
     * @param $key
     * @return mixed|null
     */
    public function get($key){
        return (isset($this->vars[$key]) ? $this->vars[$key] : null);
    }

    /**
     * @param $key
     * @return void
     */
    public function delete($key){
        unset($_SESSION[$key]);
        $this->vars = $_SESSION;
    }



}
