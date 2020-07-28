using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;

namespace Website.Frontend.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class LoginController : ControllerBase
    {
        private IConfiguration _configuration;

        public LoginController(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        [HttpGet("GetToken")]
        [Authorize(AuthenticationSchemes = "Discord")]
        public object GetJwtToken()
        {
            var userId = User.Claims.First(x => x.Type == ClaimTypes.NameIdentifier).Value;

            string key = _configuration.GetValue<string>("Jwt:EncryptionKey");
            string issuer = _configuration.GetValue<string>("Jwt:Issuer");
            string audience = _configuration.GetValue<string>("Jwt:Audience");

            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(key));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            var permClaims = new List<Claim>();
            permClaims.Add(new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()));
            permClaims.Add(new Claim("discordId", userId));

            var token = new JwtSecurityToken(issuer, audience, permClaims, null, DateTime.Now.AddDays(30), credentials);
            var jwtToken = new JwtSecurityTokenHandler().WriteToken(token);

            return new
            {
                ApiToken = jwtToken
            };
        }
    }
}
