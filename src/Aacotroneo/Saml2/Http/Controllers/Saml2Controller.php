<?php

namespace Aacotroneo\Saml2\Http\Controllers;

use Aacotroneo\Saml2\Events\Saml2LoginEvent;
use Aacotroneo\Saml2\Saml2Auth;
use Illuminate\Routing\Controller;
use Illuminate\Http\Request;
use Cookie;  //NEEDED TO JIMMY-RIG LOGIN FROM WALTS COOKIE

class Saml2Controller extends Controller
{

    protected $saml2Auth;

    /**
     * @param Saml2Auth $saml2Auth injected.
     */
    function __construct(Saml2Auth $saml2Auth)
    {
        $this->saml2Auth = $saml2Auth;
    }


    /**
     * Generate local sp metadata
     * @return \Illuminate\Http\Response
     */
    public function metadata()
    {

        $metadata = $this->saml2Auth->getMetadata();

        return response($metadata, 200, ['Content-Type' => 'text/xml']);
    }

    /**
     * Process an incoming saml2 assertion request.
     * Fires 'Saml2LoginEvent' event if a valid user is Found
     */
    public function acs()
    {
        $errors = $this->saml2Auth->acs();
        if (!empty($errors)) {
            logger()->error('Saml2 error_detail', ['error' => $this->saml2Auth->getLastErrorReason()]);
            session()->flash('saml2_error_detail', [$this->saml2Auth->getLastErrorReason()]);

            logger()->error('Saml2 error', $errors);
            session()->flash('saml2_error', $errors);
            return redirect(config('saml2_settings.errorRoute'));
        }
        $user = $this->saml2Auth->getSaml2User();
	$attributes_needed = $user->getAttributes();
	session(['SAML_NAMEID' => $attributes_needed['email'][0]]);
	
        event(new Saml2LoginEvent($user, $this->saml2Auth));
        $redirectUrl = $user->getIntendedUrl();

        if ($redirectUrl !== null) {
            return redirect($redirectUrl);
        } else {

            return redirect(config('saml2_settings.loginRoute'));
        }
    }

    /**
     * Process an incoming saml2 logout request.
     * Fires 'saml2.logoutRequestReceived' event if its valid.
     * This means the user logged out of the SSO infrastructure, you 'should' log him out locally too.
     */
    public function sls()
    {
        $error = $this->saml2Auth->sls(config('saml2_settings.retrieveParametersFromServer'));
        if (!empty($error)) {
		//dd($error);
            throw new \Exception(print_r($error, true));
        }
	//remove session variable
	session()->flush();	
        return redirect(config('saml2_settings.logoutRoute')); //may be set a configurable default
    }

    /**
     * This initiates a logout request across all the SSO infrastructure.
     */
    public function logout(Request $request)
    {
        $returnTo = $request->query('returnTo');
        $sessionIndex = $request->query('sessionIndex');
	//original next line, but w Okta its different (line after)
        //$nameId = $request->query('nameId');
	$nameId = session('SAML_NAMEID');
        $this->saml2Auth->logout($returnTo, $nameId, $sessionIndex); //will actually end up in the sls endpoint
    }


    /**
     * This initiates a login request
     * origin login()
     */
    public function login()
    {
	    
	$url_value = Cookie::get('login_source');
	if(empty($url_value)){
		$url_value = config('saml2_settings.loginRoute');
	}		
	    //orig
	//config('saml2_settings.loginRoute');	
	$this->saml2Auth->login($url_value);
	      
	//$this->saml2Auth->login(config('saml2_settings.loginRoute'));
    }

    public function login_with_path(Request $request)
    {
	    error_log("IN NEW SAML LOGIN TEST");
	    error_log("Request path is: " . $request->path);
	    //$request->path
	$this->saml2Auth->login("products/server");
    }
}

