using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace btap_xacthuc.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly IConfiguration _config;

        public AuthController(IConfiguration config)
        {
            _config = config;
        }

        // ===================== OAUTH2 GOOGLE =====================
        [HttpGet("login-google")]
        public IActionResult LoginGoogle()
        {
            var properties = new AuthenticationProperties
            {
                RedirectUri = Url.Action("GoogleResponse")
            };
            return Challenge(properties, GoogleDefaults.AuthenticationScheme);
        }

        [HttpGet("google-response")]
        public async Task<IActionResult> GoogleResponse()
        {
            var result = await HttpContext.AuthenticateAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            if (!result.Succeeded)
            {
                return BadRequest("Đăng nhập Google thất bại!");
            }

            var claims = result.Principal.Identities.FirstOrDefault()?.Claims;
            var email = claims?.FirstOrDefault(c => c.Type == ClaimTypes.Email)?.Value ?? "GoogleUser";
            var name = claims?.FirstOrDefault(c => c.Type == ClaimTypes.Name)?.Value ?? email;

            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);

            // Sinh JWT Token cho tài khoản Google (gán Role là User)
            var jwtToken = GenerateJwtToken(email, "User");

            // Redirect về trang chủ kèm token
            return Redirect($"/?token={jwtToken}&user={Uri.EscapeDataString(name)}&provider=Google");
        }

        // ===================== ĐĂNG NHẬP TRUYỀN THỐNG =====================
        public class LoginModel
        {
            public string Username { get; set; } = string.Empty;
            public string Password { get; set; } = string.Empty;
        }

        [HttpPost("login")]
        public IActionResult Login([FromBody] LoginModel model)
        {
            string role = "";
            if (model.Username == "admin" && model.Password == "123456") role = "Admin";
            else if (model.Username == "user" && model.Password == "123456") role = "User";
            else return Unauthorized(new { message = "Sai tên đăng nhập hoặc mật khẩu!" });

            var token = GenerateJwtToken(model.Username, role);
            return Ok(new { message = "Đăng nhập thành công!", token, username = model.Username, role });
        }

        // ===================== API KIỂM TRA PHÂN QUYỀN =====================
        [HttpGet("admin-data")]
        [Authorize(Roles = "Admin")]
        public IActionResult GetAdminData() => Ok(new { message = "Authorized: Dành riêng cho ADMIN!" });

        [HttpGet("user-data")]
        [Authorize(Roles = "User,Admin")]
        public IActionResult GetUserData() => Ok(new { message = "Authorized: Dành cho USER và ADMIN!" });

        // Hàm sinh JWT
        private string GenerateJwtToken(string username, string role)
        {
            var claims = new[]
            {
                new Claim(ClaimTypes.Name, username),
                new Claim(ClaimTypes.Role, role)
            };

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["Jwt:Key"]!));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
                issuer: _config["Jwt:Issuer"],
                audience: _config["Jwt:Audience"],
                claims: claims,
                expires: DateTime.UtcNow.AddMinutes(30),
                signingCredentials: creds
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }
    }
}