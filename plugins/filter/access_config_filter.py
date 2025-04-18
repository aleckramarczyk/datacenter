from ansible.errors import AnsibleFilterError 
from typing import List, Literal, Annotated, Any
from pydantic import BaseModel, computed_field, StringConstraints
from typing import Union

class StaticEPGBinding(BaseModel):
    """
    Model representing a static EPG binding.
    """
    epg: str
    encap: int
    tenant: str = None
    ap: str = None
    interface_mode: Literal["802.1p", "access", "native", "regular", "tagged", "trunk", "untagged"] = 'trunk'
    deploy_immediacy: Literal['immediate', 'lazy'] = 'immediate'
    interface: str = None
    leafs: Union[str, List[str]] = None
    interface_type: Literal['fex', 'port_channel', 'switch_port', 'vpc', 'fex_port_channel', 'fex_vpc'] = 'switchport'
    state: Literal['absent', 'present'] = 'present'
    pod: int = None

AccessPortNameString = Annotated[str, StringConstraints(pattern=r'^\d+/\d+/\d+/\d+$')]

class AccessPort(BaseModel):
    """
    Model representing an access port.
    """
    name: AccessPortNameString
    description: str = ''
    enabled: bool = True
    static_epg_bindings: List[StaticEPGBinding] = []
    interface_policy_group: str = None
    locate: bool = False
    state: Literal['absent', 'present'] = 'present'
    
    @computed_field
    @property
    def pod(self) -> int:
        parts =  self.name.split('/')
        return int(parts[0])

    @computed_field
    @property
    def leaf(self) -> int:
        parts = self.name.split('/')
        return int(parts[1])
    
    @computed_field
    @property
    def module(self) -> int:
        parts = self.name.split('/')
        return int(parts[2])

    @computed_field
    @property
    def port(self) -> int:
        parts = self.name.split('/')
        return int(parts[3])

    @computed_field
    @property
    def interface(self) -> str:
        """
        Returns the interface name in the format 'module/port'.
        """
        return f'{self.module}/{self.port}'
    
    @computed_field
    @property
    def phys_dn(self) -> str:
        """
        Returns the physical DN of the access port
        """
        return f'topology/pod-{self.pod}/node-{self.leaf}/sys/phys-[eth{self.interface}]'

    def model_post_init(self, context: Any) -> None:
        """
        Post-initialization hook for the AccessPort model.
        """
        for sepg in self.static_epg_bindings:
            sepg.interface_type = 'switch_port'
            sepg.interface = self.interface
            sepg.leafs = str(self.leaf)
            sepg.pod = self.pod
            sepg.state = self.state

class InterfacePolicyGroup(BaseModel):
    name: str = None
    link_level_policy: str = None
    cdp_policy: str = None
    lldp_policy: str = None
    port_channel_policy: str = None

PortString = Annotated[str, StringConstraints(pattern=r'^\d+/\d+$')]

class VPC_Port(BaseModel):
    """
    Model representing a VPC port.
    """
    name: PortString
    description: str = ''
    state: Literal['absent', 'present'] = 'present'
    vpc_id: int = None
    interface_policy_group: str = None

    @computed_field
    @property
    def module(self) -> int:
        parts = self.name.split('/')
        return int(parts[0])
    
    @computed_field
    @property
    def port(self) -> int:
        parts = self.name.split('/')
        return int(parts[1])

class VPC(BaseModel):
    """
    Model representing a VPC.
    """
    name: str
    vpc_id: int
    ports: List[VPC_Port] = []
    interface_policy_group: InterfacePolicyGroup = None
    static_epg_bindings: List[StaticEPGBinding] = []
    state: Literal['absent', 'present'] = 'present'

    def model_post_init(self, context: Any) -> None:
        """
        Post-initialization hook for the VPC model.
        """
        if self.interface_policy_group is None:
            self.interface_policy_group = InterfacePolicyGroup(name=f"VPC_{self.name}_IntPolGrp")
        else:
            self.interface_policy_group.name = f"VPC_{self.name}_IntPolGrp"
        
        for sepg in self.static_epg_bindings:
            sepg.interface = self.interface_policy_group.name 
            sepg.leafs = self.vpc_id
            sepg.interface_type = 'vpc'
            sepg.state = self.state
        
        for port in self.ports:
            port.vpc_id = self.vpc_id
            port.interface_policy_group = self.interface_policy_group.name
            port.state = self.state
        
class AccessConfig:
    """
    Class representing access configuration.
    """
    def __init__(self, access_config_data: dict):
        self.targeted_access_port_names = []
        self.access_ports: List[AccessPort] = []
        self.vpcs: List[VPC] = []
        self.static_epg_bindings: List[StaticEPGBinding] = []
        self.vpc_ports: List[dict] = []

        for i in access_config_data:
            if 'access_port' in i:
                ap = i['access_port']
                if 'name' in ap:
                    try: 
                        if ap['name'] in self.targeted_access_port_names:
                            raise AnsibleFilterError(f'Access config contains multiple references to the same access port: {ap["name"]}')
                        else:
                            self.targeted_access_port_names.append(ap['name'])
                        self.access_ports.append(AccessPort(**ap))
                    except Exception as e:
                        raise AnsibleFilterError(f'Error in access port {ap}: {e}')
                elif 'range' in ap:
                    try:
                        range_string = ap['range']
                        range_prefix = range_string.rsplit('/', 1)[0]
                        range_postfix = range_string.rsplit('/', 1)[1]
                        range_start = int(range_postfix.split('-')[0])
                        range_end = int(range_postfix.split('-')[1])
                        for i in range(range_start, range_end + 1):
                            ap['name'] = f"{range_prefix}/{i}"
                            if ap['name'] in self.targeted_access_port_names:
                                raise AnsibleFilterError(f'Access config contains multiple references to the same access port: {ap["name"]}')
                            else:
                                self.targeted_access_port_names.append(ap['name'])
                            self.access_ports.append(AccessPort(**ap))
                    except Exception as e:
                        raise AnsibleFilterError(f'Error in access port range {ap}: {e}')
            
            elif 'vpc' in i:
                self.vpcs.append(VPC(**i['vpc']))
            else:
                raise AnsibleFilterError(f'Unknown access config type: {i}')
        
        for ap in self.access_ports:
            for sepg in ap.static_epg_bindings:
                self.static_epg_bindings.append(sepg)

        for vpc in self.vpcs:
            for sepg in vpc.static_epg_bindings:
                self.static_epg_bindings.append(sepg)

            for port in vpc.ports:
                self.vpc_ports.append(port.model_dump())
    
    def dump(self) -> dict:
        """
        Returns a dictionary representation of the AccessConfig instance.
        """
        access_ports = []
        vpcs = []
        static_epg_bindings = []

        for access_port in self.access_ports:
            access_ports.append(access_port.model_dump())

        for vpc in self.vpcs:
            vpcs.append(vpc.model_dump())
        
        for static_epg_binding in self.static_epg_bindings:
            static_epg_bindings.append(static_epg_binding.model_dump())

        return {
            'access_ports': access_ports,
            'vpcs': vpcs,
            'static_epg_bindings': static_epg_bindings,
            'vpc_ports': self.vpc_ports
        }

class FilterModule(object):
    def filters(self):
        """
        Returns a dictionary of filter functions to be used in Ansible.
        """
        return {
            'access_config_filter': self.access_config_filter,
        }
    
    def access_config_filter(self, access_config_data):
        """
        Filters and processes access configuration data from a YAML structure.

        Args:
            access_config_yaml (dict): A dictionary containing access configuration data.

        Returns:
            dict: A dictionary containing processed access configuration data.

        Raises:
            AnsibleFilterError: If there is an error in processing the data.
        """
        try:
            access_config = AccessConfig(access_config_data)

        except Exception as e:
            raise AnsibleFilterError(f'Error in access_config_filter: {e}')

        return access_config.dump()
