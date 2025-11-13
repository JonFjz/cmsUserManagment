using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace cmsUserManagment.Infrastructure.Migrations
{
    /// <inheritdoc />
    public partial class removingjwtstoringindb : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "Token",
                table: "RefreshTokens");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "Token",
                table: "RefreshTokens",
                type: "longtext",
                nullable: false)
                .Annotation("MySql:CharSet", "utf8mb4");
        }
    }
}
