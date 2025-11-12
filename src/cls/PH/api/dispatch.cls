Class PH.api.dispatch Extends %CSP.REST
{

Parameter CONTENTTYPE = "application/json";

Parameter HandleCorsRequest = 1;

XData UrlMap
{
<Routes>
    <Route Url="/auth/login" Method="POST" Call="getLoginResponse"/>
    <Route Url="/auth/refresh" Method="GET" Call="getRefreshResponse"/>
    <Route Url="/auth/users" Method="GET" Call="getUsersResponse"/>
    <Route Url="/auth/logout" Method="GET" Call="getLogoutResponse"/>
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

    set refreshToken = user.generateRefreshToken()
    do %response.SetCookie("refresh_token", refreshToken, "", "/", "", 0, 1, "Strict")

    write user.getLoginResponseObject().%ToJSON()
    return $$$OK
}

ClassMethod getRefreshResponse() As %Status
{
    set refreshToken = %request.GetCookie("refresh_token")
    set user = ##class(PH.model.auth.phUser).createForRefreshToken(refreshToken)
    if ('$IsObject(user)) {
        set %response.Status = 401
        Quit $$$OK
    }

    write user.getLoginResponseObject().%ToJSON()
    Quit $$$OK
}

ClassMethod getLogoutResponse() As %Status
{
    set refreshToken = %request.GetCookie("refresh_token")
    do ##class(PH.db.auth.refreshToken).deleteForToken(refreshToken)
    do %response.SetCookie("refresh_token", "", "", "/", "", 0, 1, "Strict")

    write {"status": "loggedOut"}.%ToJSON()
    Quit $$$OK
}

ClassMethod getUsersResponse() As %Status
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

    set responseObject = []
    do responseObject.%Push({
        "email": "admin@prophat.com",
        "access_role": "admin",
        "created_at": "2024-01-01 12:00:00",
        "firstname": "Admin",
        "lastname": "User"
    })

    write responseObject.%ToJSON()
    return $$$OK
}

ClassMethod isValidJwt(token As %String) As %Boolean [ Language = python ]
{
    import ph.utils.auth
    return ph.utils.auth.is_jwt_valid(token)
}

}
