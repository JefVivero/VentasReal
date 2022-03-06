using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using WSVentas.Models;
using WSVentas.Models.Common;
using WSVentas.Models.Request;
using WSVentas.Models.Response;
using WSVentas.Tools;

namespace WSVentas.Services
{
    public class UserService : IUserService
    {
        private readonly AppSettings _appSetting;

        public UserService(IOptions<AppSettings> appSetting)
        {
            _appSetting = appSetting.Value;
        }

        public UserResponse Auth(AuthRequest model)
        {
            UserResponse userresponse = new UserResponse();
            using (var db = new VentaRealContext())
            {
                string spassword = Encrypt.GetSHA256(model.Password);
                var user = db.Usuarios.Where(u=> u.Email == model.Email && 
                                                 u.Password == spassword).FirstOrDefault();
                if (user == null) return null;

                userresponse.Email = user.Email;
                userresponse.Token = GetToken(user);
            }
            return userresponse;
        }

        private string GetToken(Usuario usuario)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var llave = Encoding.ASCII.GetBytes(_appSetting.Secreto);
            var tokendescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(
                        new Claim[]
                        {
                            new Claim(ClaimTypes.NameIdentifier, usuario.Id.ToString()),
                            new Claim(ClaimTypes.Email, usuario.Email)
                        }
                    ),
                Expires = DateTime.UtcNow.AddDays(60),
                SigningCredentials = new SigningCredentials( new SymmetricSecurityKey(llave), SecurityAlgorithms.HmacSha256Signature)
            };

            var token = tokenHandler.CreateToken(tokendescriptor);

            return tokenHandler.WriteToken(token);

        }
    }
}
