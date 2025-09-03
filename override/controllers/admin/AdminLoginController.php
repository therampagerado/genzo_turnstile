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

        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, 'https://challenges.cloudflare.com/turnstile/v0/siteverify');
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $data);
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 3);
        curl_setopt($ch, CURLOPT_TIMEOUT, 3);

        $result = json_decode(curl_exec($ch), true);

        return isset($result['success']) && $result['success'];
    }
}
