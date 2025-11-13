using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace cmsUserManagment.Infrastructure.Migrations
{
    /// <inheritdoc />
    public partial class asdfaslkdfjaklsdjf : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "twoFactorSecrect",
                table: "Users");

            migrationBuilder.AddColumn<bool>(
                name: "IsTwoFactorEnabled",
                table: "Users",
                type: "tinyint(1)",
                nullable: false,
                defaultValue: false);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "IsTwoFactorEnabled",
                table: "Users");

            migrationBuilder.AddColumn<string>(
                name: "twoFactorSecrect",
                table: "Users",
                type: "longtext",
                nullable: true)
                .Annotation("MySql:CharSet", "utf8mb4");
        }
    }
}
