using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;

namespace JwtWebApi.Controllers
{
    [Route("api/auth")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        public static User user = new User();
        private readonly IConfiguration _configuration;
        private readonly IUserService _userService;

        public AuthController(IConfiguration configuration, IUserService userService)
        {
            _configuration = configuration;
            _userService = userService;
        }

        [HttpGet("getName"), Authorize]
        public async Task<ActionResult<string>> GetName()
        {
            var username = _userService.GetName();
            return Ok(username);
        }

        [HttpPost("register")]
        public async Task<ActionResult<User>> Register([FromBody] UserDto registerRequest)
        {
            CreatePasswordHash(registerRequest.Password, out byte[] passwordHash, out byte[] passwordSalt);

            user.Username = registerRequest.Username;
            user.PasswordHash = passwordHash;
            user.PasswordSalt = passwordSalt;

            return Ok(user);
        }

        [HttpPost("login")]
        public async Task<ActionResult<string>> Login([FromBody] UserDto loginRequest)
        {
            if (loginRequest.Username != user.Username || !VerifyPasswordHash(loginRequest.Password, user.PasswordHash, user.PasswordSalt))
            {
                return BadRequest("Username or password is incorrect");
            }
            string token = GenerateToken(user);
            //Response.Cookies.Append("X-Access-Token", token, new CookieOptions() { HttpOnly = true, SameSite = SameSiteMode.Strict });
            //Response.Cookies.Append("X-Username", loginRequest.Username, new CookieOptions() { HttpOnly = true, SameSite = SameSiteMode.Strict });
            return Ok(token);
        }

        private string GenerateToken(User user)
        {
            List<Claim> claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, user.Username),
                new Claim(ClaimTypes.Role, "ADMIN")
            };

            var key = new SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes(_configuration.GetSection("AppSettings:Token").Value));
            var cred = new SigningCredentials(key, SecurityAlgorithms.HmacSha512Signature);
            var token = new JwtSecurityToken(
                claims: claims,
                expires: DateTime.Now.AddDays(1),
                signingCredentials: cred);
            var jwt = new JwtSecurityTokenHandler().WriteToken(token);

            return jwt;
        }

        private void CreatePasswordHash(string password, out byte[] passwordHash, out byte[] passwordSalt)
        {
            using (var hmac = new HMACSHA512())
            {
                passwordSalt = hmac.Key;
                passwordHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
            }
        }

        private bool VerifyPasswordHash(string requestPassword, byte[] userPasswordHash, byte[] userPasswordSalt )
        {
            using (var hmac = new HMACSHA512(userPasswordSalt))
            {
                var requestPasswordHashed = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(requestPassword));
                return requestPasswordHashed.SequenceEqual(userPasswordHash);
            }
        }

    }
}
