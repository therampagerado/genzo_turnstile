<?php
/**
 * Override AdminLoginController to add Cloudflare Turnstile validation
 */

class AdminLoginController extends AdminLoginControllerCore
{
    public function setMedia()
    {
        parent::setMedia();

        if ($this->isTurnstileActive()) {
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

    public function postProcess()
    {
        if ($this->isTurnstileActive() && (Tools::isSubmit('submitLogin') || Tools::isSubmit('submitForgot'))) {
            if (!$this->validateFormSubmitToken()) {
                $this->errors[] = $this->l('Captcha Validation failed');
                return;
            }
        }

        parent::postProcess();
    }

    private function isTurnstileActive()
    {
        return Module::isInstalled('genzo_turnstile')
            && Module::isEnabled('genzo_turnstile')
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
