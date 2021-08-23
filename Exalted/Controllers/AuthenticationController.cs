using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using LongVision.Business.Entity;
using LongVision.Business.Model;
using LongVision.Persistent;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;

namespace LongVision.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthenticationController : ControllerBase
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IConfiguration _configuration;

        public AuthenticationController(UserManager<ApplicationUser> user, 
            RoleManager<IdentityRole> role,
            IConfiguration configuration)
        {
            _userManager = user;
            _roleManager = role;
            _configuration = configuration;
        }

        [HttpPost]
        [Route("Login")]
        public async Task<IActionResult> Login([FromBody] LoginModel login)
        {
            var user = await _userManager.FindByNameAsync(login.UserName);
            if (user != null && await _userManager.CheckPasswordAsync(user, login.Password))
            {
                var userRoles = await _userManager.GetRolesAsync(user);
                var authenticationClaim = new List<Claim>
                {
                    new Claim(ClaimTypes.Name, user.UserName),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
                };
                foreach (var role in userRoles)
                {
                   authenticationClaim.Add(new Claim(ClaimTypes.Role, role));
                }

                var signingKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Secret"]));
                var token = new JwtSecurityToken(
                    issuer:_configuration["JWT:ValidIssuer"] ,
                    audience:_configuration["JWT:ValidAudience"],
                    expires:DateTime.Now.AddHours(5),
                    claims:authenticationClaim,
                    signingCredentials:new SigningCredentials(signingKey, SecurityAlgorithms.HmacSha256)
                );

                return Ok(new {token = new JwtSecurityTokenHandler().WriteToken(token), expiration = token.ValidTo});
            }

            return Unauthorized();
        }

        [HttpPost]
        [Route("RegisterUser")]
        public async Task<IActionResult> RegisterUser([FromBody] RegisterModel register)
        {
            var isUserExist = await _userManager.FindByNameAsync(register.UserName);
            if (isUserExist != null)
                return StatusCode(StatusCodes.Status500InternalServerError,
                    new Response {Status = "Error", Message = "User Already Exist"});

            var applicationUser = new ApplicationUser()
            {
                Email = register.Email,
                UserName = register.UserName,
                SecurityStamp = Guid.NewGuid().ToString()
            };
            var result = await _userManager.CreateAsync(applicationUser,register.Password);
            if (!result.Succeeded)
                return StatusCode(StatusCodes.Status500InternalServerError,
                    new Response() {Status = "Error", Message = "User creation unsuccessfully"});

            return Ok(new Response() {Status = "Success", Message = "User creation successfully"});
        }

        [HttpPost]
        [Route("RegisterAdmin")]
        public async Task<IActionResult> RegisterAdmin([FromBody] RegisterModel register)
        {
            var adminRegistered = await _userManager.FindByNameAsync(register.UserName);
            if (adminRegistered != null)
                return StatusCode(StatusCodes.Status500InternalServerError,
                    new Response() {Status = "Error", Message = "Admin already Exist"});

            var applicationUser = new ApplicationUser()
            {
                UserName = register.UserName,
                Email = register.Email,
                SecurityStamp = Guid.NewGuid().ToString()
            };

            var result = await _userManager.CreateAsync(applicationUser, register.Password);
            if (!result.Succeeded)
                return StatusCode(StatusCodes.Status500InternalServerError,
                    new Response() {Status = "Error", Message = "Admin creation unsuccessfully"});

            if (!await _roleManager.RoleExistsAsync(UserRoles.Admin))
                await _roleManager.CreateAsync(new IdentityRole(UserRoles.Admin));

            if (!await _roleManager.RoleExistsAsync(UserRoles.User))
                await _roleManager.CreateAsync(new IdentityRole(UserRoles.User));

            if (await _roleManager.RoleExistsAsync(UserRoles.Admin))
                await _userManager.AddToRoleAsync(applicationUser, UserRoles.Admin);
            return Ok(new Response() {Status = "Success", Message = "Admin created successfully"});

        }

    }
}
