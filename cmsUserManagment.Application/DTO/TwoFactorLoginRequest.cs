namespace cmsUserManagment.Application.DTO
{
    public class TwoFactorLoginRequest
    {
        public Guid LoginId { get; set; }
        public string Code { get; set; } = string.Empty;
    }
}
