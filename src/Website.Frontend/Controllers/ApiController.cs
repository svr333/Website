using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Website.Frontend.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    [Authorize]
    public class ApiController : ControllerBase
    {
        [HttpGet("current")]
        public object Current()
            => new
            {
                Never = "Gonna Give You Up",
                Always = "Gonna Let You Down",
                Sometimes = "Gonna Run Around",
                Regularly = "Gonna Desert You"
            };
    }
}
