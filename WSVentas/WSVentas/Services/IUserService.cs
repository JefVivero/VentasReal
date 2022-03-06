using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using WSVentas.Models.Request;
using WSVentas.Models.Response;

namespace WSVentas.Services
{
    public interface IUserService
    {
        UserResponse Auth(AuthRequest model); 
    }
}
