namespace cmsUserManagment.Application.Exceptions;

public class AuthExecption : Exception
{
    public AuthExecption(int code, string message, params object[] ars) : base(message)
    {
    }

}
