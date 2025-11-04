Class PH.Service Extends %CSP.REST
{

Parameter CONTENTTYPE = "application/json";

XData UrlMap
{
<Routes>
    <Route Url="/auth/login" Method="GET" Call="getLoginResponse"/>
    <Route Url="/auth/validate" Method="GET" Call="getValidateResponse"/>
</Routes>
}

ClassMethod getLoginResponse() As %Status
{
    set email = %request.Get("email")
    set user = ##class(PH.model.auth.phUser).createForEmail(email)
    if ('$IsObject(user)) {
        set %response.Status = 401
        return $$$OK
    }

    set password = %request.Get("password")
    if ('user.isPasswordCorrect(password)) {
        set %response.Status = 401
        return $$$OK
    }

    write user.getLoginResponseObject().%ToJSON()
    return $$$OK
}

ClassMethod getValidateResponse() As %Status
{
    set header = %request.GetCgiEnv("HTTP_AUTHORIZATION")
    If header="" {
        set %response.Status = 401
        Quit $$$OK
    }

    Set token = $Piece(header," ",2)
    If token="" {
        set %response.Status = 401
        Quit $$$OK
    }

    set isValid = ..isValidJwt(token)
    if 'isValid {
        set %response.Status = 401
        Quit $$$OK
    }

    set responseObject = {}
    set responseObject.valid = isValid

    write responseObject.%ToJSON()
    return $$$OK
}

ClassMethod isValidJwt(token As %String) As %Boolean [ Language = python ]
{
    import ph.utils.auth
    return ph.utils.auth.is_jwt_valid(token)
}

}
