<?php
/**
 * Override AdminLoginController to add Cloudflare Turnstile validation
 */

class AdminLoginController extends AdminLoginControllerCore
{
    /**
     * Add Turnstile assets on the admin login page
     */
    public function setMedia()
    {
        parent::setMedia();

        if ($this->shouldCheckTurnstile()) {
            Media::addJsDef([
                'turnstileSiteKey' => Configuration::get('GENZO_TURNSTILE_SITE_KEY'),
                'submitsToCheck'   => [
                    'submitLogin'  => true,
                    'submitForgot' => true,
                ],
                'turnstileActive' => true,
            ]);

            $module = Module::getInstanceByName('genzo_turnstile');
            if ($module instanceof Module) {
                $this->addJS($module->getPathUri() . 'views/js/genzo_turnstile.js');
            }
        }
    }

    /**
     * Validate the Turnstile response during login submissions
     */
    public function processLogin()
    {
        if ($this->shouldCheckTurnstile()) {
            if (!$this->validateFormSubmitToken()) {
                $this->errors[] = $this->l('Your captcha was wrong. Please try again.');
            }
        }

        return parent::processLogin();
    }

    /**
     * Validate the Turnstile response during password recovery submissions
     */
    public function processForgot()
    {
        if ($this->shouldCheckTurnstile()) {
            if (!$this->validateFormSubmitToken()) {
                $this->errors[] = $this->l('Your captcha was wrong. Please try again.');
            }
        }

        return parent::processForgot();
    }

    private function shouldCheckTurnstile()
    {
        return Module::isEnabled('genzo_turnstile')
            && @filemtime(_PS_MODULE_DIR_.'genzo_turnstile/genzo_turnstile.php')
            && Configuration::get('GENZO_TURNSTILE_SITE_KEY')
            && Configuration::get('GENZO_TURNSTILE_SECRET_KEY');
    }

    private function validateFormSubmitToken()
    {
        $data = [
            'secret'   => Configuration::get('GENZO_TURNSTILE_SECRET_KEY'),
            'response' => Tools::getValue('cf-turnstile-response'),
        ];

        $payload = http_build_query($data);
        $url     = 'https://challenges.cloudflare.com/turnstile/v0/siteverify';

        if (function_exists('curl_init')) {
            $ch = curl_init();
            curl_setopt($ch, CURLOPT_URL, $url);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch, CURLOPT_POST, true);
            curl_setopt($ch, CURLOPT_POSTFIELDS, $payload);
            curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 3);
            curl_setopt($ch, CURLOPT_TIMEOUT, 3);
            $response = curl_exec($ch);
            curl_close($ch);
        } else {
            $options = [
                'http' => [
                    'method'  => 'POST',
                    'header'  => "Content-type: application/x-www-form-urlencoded\r\n",
                    'content' => $payload,
                    'timeout' => 3,
                ],
            ];
            $context  = stream_context_create($options);
            $response = Tools::file_get_contents($url, false, $context);
        }

        $result = json_decode($response, true);

        return isset($result['success']) && $result['success'];
    }
}
