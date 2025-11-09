namespace cmsUserManagment.Application.Common.ErrorCodes;

public class ContentErrorCodes
{
    public int code;
    public string message;

    private ContentErrorCodes(int code, string message)
    {
        this.code = code;
        this.message = message;
    }

    public static readonly ContentErrorCodes genc = new(1, "stupid");
}
